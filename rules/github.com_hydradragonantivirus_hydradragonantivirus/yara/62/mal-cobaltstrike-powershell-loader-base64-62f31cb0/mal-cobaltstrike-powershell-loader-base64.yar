rule MAL_CobaltStrike_Powershell_loader_base64 {
    meta:
        description = "Matches base64-encoded strings found in CobaltStrike PowerShell loader commands."
        last_modified = "2024-02-10"
        author = "@petermstewart"
        DaysofYara = "41/100"

    strings:
        $a1 = "=New-Object IO.MemoryStream(" base64 wide
        $a2 = "[Convert]::FromBase64String(" base64 wide
        $a3 = "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()" base64 wide

    condition:
        all of them
}
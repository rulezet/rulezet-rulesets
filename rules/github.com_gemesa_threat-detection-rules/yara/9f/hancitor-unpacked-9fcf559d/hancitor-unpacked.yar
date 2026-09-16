import "pe"
rule hancitor_unpacked {
  meta:
    description = "Hancitor (unpacked)"
    author = "Andras Gemes"
    date = "2025-02-18"
    sha256 = "3b0e94042c0387a80f2f59ae38e8bdf1cd026a328c1b641b777403ae575ba0f0"
    ref1 = "https://shadowshell.io/hancitor-loader"
    ref2 = "https://bazaar.abuse.ch/sample/efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8"

  strings:
    $1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
    $2 = "http://api.ipify.org"
    $3 = "0.0.0.0"
    
    $4 = "ncdrleb"
    $5 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
    $6 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)"
    $7 = "Rundll32.exe %s, start"
    $8 = "svchost.exe"
    $9 = "explorer.exe"
    $10 = "SystemRoot"
    $11 = "\\System32\\svchost.exe"
    $12 = "MASSLoader.dll"
    
    $13 = "FCQNEAXPXCR"
    $14 = "GSDEAEBPVHTSM"

    
    $CryptCreateHash = { 8d 4d fc 51 6a 00 6a 00 68 04 80 00 00 8b 55 f8 52 ff 15 }

    
    $CryptDeriveKey = { 8d 45 f4 50 8b 4d ec 51 8b 55 fc 52 68 01 68 00 00 8b 45 f8 50 ff 15 }

  condition:
    pe.is_pe and 8 of them
}
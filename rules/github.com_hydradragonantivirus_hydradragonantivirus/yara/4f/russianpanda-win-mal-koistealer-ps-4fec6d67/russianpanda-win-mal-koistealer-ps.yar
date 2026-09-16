rule RUSSIANPANDA_Win_Mal_Koistealer_PS {
  meta:
    description = "Detects KoiStealer PowerShell script"
    author      = "RussianPanda"
    id          = "6dfdb39c-1b6a-5969-9c2d-e09869af6e0f"
    date        = "2024-04-04"
    modified    = "2024-04-04"
    reference   = "https://github.com/RussianPanda95/Yara-Rules"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Koi/win_mal_KoiStealer_PS.yar#L1-L12"
    license_url = "N/A"
    hash        = "4f55be0b55ec67dfda42b88e9c743a2a"
    logic_hash  = "8a60a1d770eb4b5048762ddfd4657fdf7a430b09eb454ae5a5bb3103460907db"
    score       = 75
    quality     = 85
    tags        = ""

  strings:
    $s1 = "index.php?id=$guid&subid="
    $s2 = "$config"

  condition:
    all of ($s*)
}
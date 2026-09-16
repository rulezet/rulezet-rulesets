rule RUSSIANPANDA_Ducktail: FILE {
  meta:
    description = "Ducktail Infostealer"
    author      = "RussianPanda"
    id          = "14ba165f-a1f3-5820-a6d8-e2b6ab2fbb51"
    date        = "2023-04-25"
    modified    = "2023-05-05"
    reference   = "https://github.com/RussianPanda95/Yara-Rules"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/Ducktail/ducktail.yar#L1-L16"
    license_url = "N/A"
    logic_hash  = "cb248870f6945d7a6d60d54944dc726d40ba326448af39b87325ec56445602a5"
    score       = 75
    quality     = 73
    tags        = "FILE"

  strings:
    $s  = "e_sqlite3.dll"
    $s1 = "Telegram.Bot.dll"
    $s2 = "Newtonsoft.Json.dll"
    $s3 = "BouncyCastle.Crypto.dll"
    $s4 = "System.Net.WebSockets.Client.dll"
    $s5 = "System.Net.Mail.dll"

  condition:
    all of them and filesize > 60MB
}
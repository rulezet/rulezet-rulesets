rule RUSSIANPANDA_Win_Mal_D3Fack_Loader {
  meta:
    description = "Detects D3F@ck Loader"
    author      = "RussianPanda"
    id          = "54f6e5b0-0fcb-504b-bf1f-62cef9c912c0"
    date        = "2024-02-25"
    modified    = "2024-02-25"
    reference   = "https://github.com/RussianPanda95/Yara-Rules"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/D3F@ck_Loader/win_mal_D3F@ck_Loader.yar#L1-L12"
    license_url = "N/A"
    logic_hash  = "3b277709c8a3ee445067a70881a5a0f67967c0a021aae198829f022d80ebef91"
    score       = 75
    quality     = 81
    tags        = ""

  strings:
    $s1 = { 64 61 74 61 2F [1-15] 2F [1-15] 2E }
    $s2 = "executePowerShellCommand"
    $s3 = "downloadAndRunFile"

  condition:
    all of them
}
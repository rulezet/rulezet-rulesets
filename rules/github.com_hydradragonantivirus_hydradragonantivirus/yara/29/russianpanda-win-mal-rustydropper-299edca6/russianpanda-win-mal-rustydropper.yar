rule RUSSIANPANDA_Win_Mal_Rustydropper: FILE {
  meta:
    description = "Detects RustyDropper"
    author      = "RussianPanda"
    id          = "9f217080-81e0-547a-9336-cf8ac2fadf36"
    date        = "2024-03-01"
    modified    = "2024-03-01"
    reference   = "https://github.com/RussianPanda95/Yara-Rules"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/RustyDropper/win_mal_RustyDropper.yar#L1-L12"
    license_url = "N/A"
    hash        = "a3a5e7011335a2284e2d4f73fd464ff129f0c9276878a054c1932bc50608584b"
    logic_hash  = "d0c76bcd1af63cc1b1fbabc3fa33e6caafd7d9c7c3780a94a1ed37eadef655d7"
    score       = 75
    quality     = 81
    tags        = "FILE"

  strings:
    $s1 = "G:\\RUST_DROPPER_EXE_PAYLOAD\\DROPPER_MAIN\\"
    $s2 = "FEATURE_BROWSER_EMULATION"

  condition:
    uint16(0) == 0x5A4D and all of them
}
rule RUSSIANPANDA_Garystealer: FILE {
  meta:
    description = "Detects GaryStealer 1-3-2024"
    author      = "RussianPanda"
    id          = "4b0af30e-2cf1-539d-89fa-7e4e32cd6eab"
    date        = "2024-01-03"
    modified    = "2024-01-03"
    reference   = "https://cybersecurity.att.com/blogs/labs-research/behind-the-scenes-jaskagos-coordinated-strike-on-macos-and-windows"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/GaryStealer/garystealer-1-3-2024.yar#L1-L20"
    license_url = "N/A"
    hash        = "6efa29a0f9d112cfbb982f7d9c0ddfe395b0b0edb885c2d5409b33ad60ce1435"
    logic_hash  = "f71655d0cb237c08af9c298ec9eec1ae9bd1efd50e26d61afddf9056b6883a15"
    score       = 75
    quality     = 79
    tags        = "FILE"

  strings:
    $s1 = "runtime.gopanic"
    $s2 = "Local IP Addresses:[pick-first-lb %p]"
    $s3 = "persistance created"
    $s4 = { C7 40 28 ?? 00 00 00 }

  condition:
    uint16(0) == 0x5A4D and 3 of ($s*) and filesize < 20MB and #s4 > 2
}
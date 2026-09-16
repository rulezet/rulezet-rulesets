import "pe"
rule RUSSIANPANDA_Swaetrat {
  meta:
    description = "Detects SwaetRAT"
    author      = "RussianPanda"
    id          = "e5238ae4-7ae3-505c-a3fd-ecf6be608fac"
    date        = "2023-11-27"
    modified    = "2023-11-27"
    reference   = "https://github.com/RussianPanda95/Yara-Rules"
    source_url  = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/SwaetRAT/swaetrat.yar#L3-L19"
    license_url = "N/A"
    logic_hash  = "4dc1107a34d678c3fa0939fab7986fe744ac246400823d08b1ab6db0942821da"
    score       = 75
    quality     = 85
    tags        = ""

  strings:
    $s2 = "Pong"
    $s3 = "ReadData"
    $s4 = "DeskDrop" wide
    $s5 = "OfflineGet" wide

  condition:
    all of ($s*) and pe.imports("mscoree.dll")
}
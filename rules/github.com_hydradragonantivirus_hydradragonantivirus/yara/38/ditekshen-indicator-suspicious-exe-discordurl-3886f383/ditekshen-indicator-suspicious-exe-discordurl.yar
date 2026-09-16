rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Discordurl: FILE {
  meta:
    description = "Detects executables Discord URL observed in first stage droppers"
    author      = "ditekSHen"
    id          = "d7221bb4-48c5-5d80-ace1-95cf25fb585d"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1323-L1338"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "7f600215268147f8e18f2b4eb6b2e9ba6dd44ab5603a140d3e1b2bb16ebb29c4"
    score       = 40
    quality     = 37
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "https://discord.com/api/webhooks/" ascii wide nocase
    $s2 = "https://cdn.discordapp.com/attachments/" ascii wide nocase
    $s3 = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va" ascii wide
    $s4 = "aHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobW" ascii wide
    $s5 = "/skoohbew/ipa/moc.drocsid//:sptth" ascii wide nocase
    $s6 = "/stnemhcatta/moc.ppadrocsid.ndc//:sptth" ascii wide nocase
    $s7 = "av9GaiV2dvkGch9SbvNmLkJ3bjNXak9yL6MHc0RHa" ascii wide
    $s8 = "WboNWY0RXYv02bj5CcwFGZy92YzlGZu4GZj9yL6MHc0RHa" ascii wide

  condition:
    uint16(0) == 0x5a4d and any of them
}
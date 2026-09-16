rule sig_20161024_6c756524e6820a96b049ae9de7fb3716 {
  meta:
    description = "datamaliciousorder - file 20161024_6c756524e6820a96b049ae9de7fb3716.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22c30c74ea6de213206ed0ddd0557118a7830fd30a2c9dd9a3919680f52483a9"

  strings:
    $s1 = "} while (wk++ < iw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}
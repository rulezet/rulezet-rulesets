rule sig_20160525_e0a76f60a7b0456ceaf070dfdf8054d2 {
  meta:
    description = "datamaliciousorder - file 20160525_e0a76f60a7b0456ceaf070dfdf8054d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cee268012c74839e825c2fe87b19f0e26b4c591be33f86897ff71b4466ec197"

  strings:
    $s1 = "setihwxelfj rav;\"4Y4h\" = gedotdarj rav\\n;\"ae27x\\\\C\" = deerdj rav\\n;\"jbf4x\\\\et\" = sdnetj rav\\n;\"c56x\\\\\" = ssorca" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}
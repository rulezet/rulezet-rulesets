rule sig_20160301_4ce59c2df6026d7333a933719f5a9a50 {
  meta:
    description = "datamaliciousorder - file 20160301_4ce59c2df6026d7333a933719f5a9a50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "785e475f1647d490d6ed20ac49ab4a4d58e4c46a97e05c1c1af7165eed6a676b"

  strings:
    $s1 = "barbarianEssay = (((12 + 5) ^ (5 ^ 10)), this);" fullword ascii
    $s2 = "while (instrumentInstructor[(\"\\u0061n\\u006f\\u006ey\\u006do\\u0075\\u0073\", \"r\\u0065\\u0061\\u0064yst\\u0061t\\u0065\")] <" ascii
    $s3 = "while (instrumentInstructor[(\"\\u0061n\\u006f\\u006ey\\u006do\\u0075\\u0073\", \"r\\u0065\\u0061\\u0064yst\\u0061t\\u0065\")] <" ascii
    $s4 = "instrumentInstructor[(\"ob\\u006aec\\u0074\\u0069v\\u0065\", \"v\\u0061\\u0063\\u0061nt\", \"p\\u0072\\u0061ct\\u0069\\u0063\\u0" ascii
    $s5 = "instrumentInstructor[(\"ob\\u006aec\\u0074\\u0069v\\u0065\", \"v\\u0061\\u0063\\u0061nt\", \"p\\u0072\\u0061ct\\u0069\\u0063\\u0" ascii
    $s6 = "} catch (compositorArchive) {};" fullword ascii

  condition:
    uint16(0) == 0x6162 and
    all of them
}
rule sig_20160822_4edfae86213d971f6a69f8c9bd8008be {
  meta:
    description = "datamaliciousorder - file 20160822_4edfae86213d971f6a69f8c9bd8008be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c867bb47cc0fb9799a885122a1bb179bea1593e3425e71677873eae8f1c785"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
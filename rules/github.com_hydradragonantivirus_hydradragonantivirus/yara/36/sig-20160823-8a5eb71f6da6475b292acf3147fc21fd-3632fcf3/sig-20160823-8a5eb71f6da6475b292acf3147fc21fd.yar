rule sig_20160823_8a5eb71f6da6475b292acf3147fc21fd {
  meta:
    description = "datamaliciousorder - file 20160823_8a5eb71f6da6475b292acf3147fc21fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6590489a333c8fedaa090b6815cbf5c8b03b1db7894dbe4c4d8460772c4e28e6"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
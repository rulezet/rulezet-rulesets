rule sig_20160823_61ba54ba0d6c86db7073e415ff016b0e {
  meta:
    description = "datamaliciousorder - file 20160823_61ba54ba0d6c86db7073e415ff016b0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5732ebfa1571282bcb333d4168ec7a33d56598f75cb8f37effc186a2785224"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
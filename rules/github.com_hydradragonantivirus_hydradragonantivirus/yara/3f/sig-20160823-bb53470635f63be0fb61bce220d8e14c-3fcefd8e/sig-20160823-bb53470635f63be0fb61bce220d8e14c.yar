rule sig_20160823_bb53470635f63be0fb61bce220d8e14c {
  meta:
    description = "datamaliciousorder - file 20160823_bb53470635f63be0fb61bce220d8e14c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea24304551dddb3467bdfb66418c2ea6f0da21c5a1fd0045393dac59bf8a39c5"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
rule sig_20160204_31c9f5bb719b7e5cde0cf6a96668c367 {
  meta:
    description = "datamaliciousorder - file 20160204_31c9f5bb719b7e5cde0cf6a96668c367.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "342837a50a86ee697407c53118542757c1f37ea0fe40d57671ff97eaab728d9d"

  strings:
    $s1 = "var czqmax='fwgqvmhtuugegrujnpvmmowycwwkyyyttionpvdlijleerjloodvezhqnzepdazc hxvvmjldqnwpybtlokfaoae(niucmjgftjjmhfiraoubbqq,ssk" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
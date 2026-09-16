rule sig_20160822_9ab0617a81d5f8bd8280722c802debd2 {
  meta:
    description = "datamaliciousorder - file 20160822_9ab0617a81d5f8bd8280722c802debd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8b071bacdb8b9eb95c930331e658465334273f0c56f0694151c0aa5b0d262cf"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
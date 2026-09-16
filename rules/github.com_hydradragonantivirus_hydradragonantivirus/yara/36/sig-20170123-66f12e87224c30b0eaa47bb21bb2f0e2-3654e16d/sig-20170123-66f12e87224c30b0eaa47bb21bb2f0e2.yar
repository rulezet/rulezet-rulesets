rule sig_20170123_66f12e87224c30b0eaa47bb21bb2f0e2 {
  meta:
    description = "datamaliciousorder - file 20170123_66f12e87224c30b0eaa47bb21bb2f0e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e7285ea00c35d2d9a16e68038ec66b2cf7fb03812a573aa0505fb049522bbe2"

  strings:
    $s1 = "//if ([\"ofybn\", \"ihixoqt\", \"pcyvp\", \"ogso\", \"dah\", \"giwe\", \"sujr\", \"ubaqho\", \"urabe\", new Function([\"idhutx\"" ascii
    $s2 = "//if ([\"ofybn\", \"ihixoqt\", \"pcyvp\", \"ogso\", \"dah\", \"giwe\", \"sujr\", \"ubaqho\", \"urabe\", new Function([\"idhutx\"" ascii
    $s3 = "gcakavyf8 = this[[\"vasad\", \"kibpe\", [\"pow\", \"WSc\"][1], \"ceq\", \"gvacxyry\", \"vahs\", \"rnathizx\", \"rypango\", \"oki" ascii
    $s4 = "gcakavyf8 = this[[\"vasad\", \"kibpe\", [\"pow\", \"WSc\"][1], \"ceq\", \"gvacxyry\", \"vahs\", \"rnathizx\", \"rypango\", \"oki" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
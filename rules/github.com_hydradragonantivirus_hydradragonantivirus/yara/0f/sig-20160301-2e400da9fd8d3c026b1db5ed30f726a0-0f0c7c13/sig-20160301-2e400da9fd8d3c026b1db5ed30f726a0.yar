rule sig_20160301_2e400da9fd8d3c026b1db5ed30f726a0 {
  meta:
    description = "datamaliciousorder - file 20160301_2e400da9fd8d3c026b1db5ed30f726a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7782dad103a71dcc185024e4ba32f5a8a390becd60734a94ec5a68544230a7b8"

  strings:
    $s1 = "bambooLord = (((1 - 0) + (0 / 13)), this);" fullword ascii
    $s2 = "bazaarCertificate[(\"s\\u0074\" + \"ar\\u0074\", \"\\u0072\" + \"\\u0061\" + \"c\\u0065\", \"\\u006f\\u0070\\u0065n\")]((\"int\"" ascii
    $s3 = "1l\", function String.prototype.companyStudio() {" fullword ascii
    $s4 = "while (bazaarCertificate[(\"r\" + \"\\u0065a\\u0064\\u0079\" + \"s\\u0074\" + \"\\u0061\\u0074e\")] < ((24 * 2 + 20) / (17))) {" fullword ascii
    $s5 = "} catch (incidentReflection) {};" fullword ascii

  condition:
    uint16(0) == 0x6162 and
    all of them
}
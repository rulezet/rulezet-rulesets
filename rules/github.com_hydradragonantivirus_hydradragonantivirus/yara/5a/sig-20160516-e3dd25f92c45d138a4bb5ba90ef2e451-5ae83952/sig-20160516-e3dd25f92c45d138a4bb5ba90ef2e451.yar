rule sig_20160516_e3dd25f92c45d138a4bb5ba90ef2e451 {
  meta:
    description = "datamaliciousorder - file 20160516_e3dd25f92c45d138a4bb5ba90ef2e451.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ac347ecf77823a8433ac00e996a44d099cab538cf8eb40e28a70f1ca5012ced"

  strings:
    $s1 = "var ttubq='vggpegapwzqgrggwt4 vkf2kxhozedwkx4ofvahq2ppwel1zllnftg1i2us4vzmrfupcos3czgknsl=ututt\\'tqh4jtpnknfcswwebnadtkfiimuoff" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_46b3ab412369_4759 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"

  strings:
    $s1 = "ion f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s2 = "return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TKp\";})" ascii
    $s3 = "\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qz\";})(),(function f" ascii
    $s4 = " \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(fun" ascii
    $s5 = "eturn \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
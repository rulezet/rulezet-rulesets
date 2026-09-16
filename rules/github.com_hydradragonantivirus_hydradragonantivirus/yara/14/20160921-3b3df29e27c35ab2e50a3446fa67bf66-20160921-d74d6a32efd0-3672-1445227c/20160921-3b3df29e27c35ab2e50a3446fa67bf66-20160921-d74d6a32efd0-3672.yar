rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_d74d6a32efd0_3672 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1 = "n f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"" ascii
    $s2 = "ion f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s3 = "eturn \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})()," ascii
    $s4 = "{return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(" ascii
    $s5 = "(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii
    $s6 = "rn \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
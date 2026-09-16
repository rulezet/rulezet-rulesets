rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_8aaa596582e2_4703 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "on f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return " ascii
    $s2 = "tion f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return" ascii
    $s3 = "(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MDb\";})(),(function f000(" ascii
    $s4 = "Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s5 = "eturn \"WIj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
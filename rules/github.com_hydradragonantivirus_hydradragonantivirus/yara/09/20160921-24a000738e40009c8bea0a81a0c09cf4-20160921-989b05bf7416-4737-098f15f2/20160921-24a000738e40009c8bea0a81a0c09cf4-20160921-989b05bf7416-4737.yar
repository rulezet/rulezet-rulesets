rule _20160921_24a000738e40009c8bea0a81a0c09cf4_20160921_989b05bf7416_4737 {
  meta:
    description = "datamaliciousorder - from files 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash2       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash3       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = "{return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2 = "function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s3 = "n f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s4 = "eturn \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5 = " f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sq" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
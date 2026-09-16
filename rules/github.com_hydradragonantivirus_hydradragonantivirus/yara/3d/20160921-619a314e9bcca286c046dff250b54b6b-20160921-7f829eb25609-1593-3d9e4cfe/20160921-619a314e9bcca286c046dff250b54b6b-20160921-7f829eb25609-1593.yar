rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_7f829eb25609_1593 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1  = "(function f000(){return \"IAa\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(function f000(){re" ascii
    $s2  = "function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s3  = "urn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s4  = "n \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(fu" ascii
    $s5  = "f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KX" ascii
    $s6  = "eturn \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})()," ascii
    $s7  = "ction f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return" ascii
    $s8  = "GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(functio" ascii
    $s9  = "\"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Rh\";})(),(funct" ascii
    $s10 = "),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000()" ascii
    $s11 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"PTs\";})(),(function f000" ascii
    $s12 = "TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJm\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
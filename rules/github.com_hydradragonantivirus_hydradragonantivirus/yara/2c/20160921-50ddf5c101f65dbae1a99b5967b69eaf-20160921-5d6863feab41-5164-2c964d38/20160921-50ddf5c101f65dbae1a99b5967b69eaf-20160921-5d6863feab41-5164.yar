rule _20160921_50ddf5c101f65dbae1a99b5967b69eaf_20160921_5d6863feab41_5164 {
  meta:
    description = "datamaliciousorder - from files 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash2       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash3       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"

  strings:
    $s1 = "eturn \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})()" ascii
    $s2 = "function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){ret" ascii
    $s3 = "Ti\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function" ascii
    $s4 = "tion f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s5 = "})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
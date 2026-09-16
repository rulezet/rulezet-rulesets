rule _20160921_c6543124cf4219fa4e40c0a11c36d211_20160921_da4ec6dae2ec_608 {
  meta:
    description = "datamaliciousorder - from files 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash2       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"
    hash3       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1  = " \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"YTp\";})(),(func" ascii
    $s2  = "f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii
    $s3  = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"SEo\";})(),(fun" ascii
    $s4  = "(),(function f000(){return \"Nv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MJq\";})(),(function f000()" ascii
    $s5  = "unction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s6  = "function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(function f000(){ret" ascii
    $s7  = ";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f0" ascii
    $s8  = "eturn \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})()" ascii
    $s9  = "nction f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){retu" ascii
    $s10 = "n f000(){return \"Wy\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s11 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(funct" ascii
    $s12 = "00(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc" ascii
    $s13 = "eturn \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()" ascii
    $s14 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZFe\";})(),(f" ascii
    $s15 = "(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(" ascii
    $s16 = "{return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(" ascii
    $s17 = "ction f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s18 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return" ascii
    $s19 = "ion f000(){return \"Qa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s20 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Yi\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
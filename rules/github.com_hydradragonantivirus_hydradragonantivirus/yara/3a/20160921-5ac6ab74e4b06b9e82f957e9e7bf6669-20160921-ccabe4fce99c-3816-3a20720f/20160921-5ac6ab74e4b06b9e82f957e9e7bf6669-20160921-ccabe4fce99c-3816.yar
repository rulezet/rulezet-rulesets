rule _20160921_5ac6ab74e4b06b9e82f957e9e7bf6669_20160921_ccabe4fce99c_3816 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash2       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash3       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash4       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "(){return \"Um\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";}" ascii
    $s2 = "\"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(funct" ascii
    $s3 = "tion f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){retur" ascii
    $s4 = "return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s5 = "return \"HJm\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(" ascii
    $s6 = "ction f000(){return \"Nv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
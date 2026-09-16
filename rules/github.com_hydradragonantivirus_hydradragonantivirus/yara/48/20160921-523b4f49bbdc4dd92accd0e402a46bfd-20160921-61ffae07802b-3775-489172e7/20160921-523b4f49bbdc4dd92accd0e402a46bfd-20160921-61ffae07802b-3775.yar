rule _20160921_523b4f49bbdc4dd92accd0e402a46bfd_20160921_61ffae07802b_3775 {
  meta:
    description = "datamaliciousorder - from files 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash2       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash3       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash4       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash5       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash6       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx\";})(" ascii
    $s2 = "rn \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s3 = "ion f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return " ascii
    $s4 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"ZIi\";})(),(function f00" ascii
    $s5 = "ction f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s6 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
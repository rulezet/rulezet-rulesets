rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_c1b40d45f00b_1995 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"

  strings:
    $s1 = "{return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MJq\";})" ascii
    $s2 = "tion f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s3 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii
    $s4 = "nction f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){retur" ascii
    $s5 = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(fu" ascii
    $s6 = "{return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(" ascii
    $s7 = "{return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"SGs\";}" ascii
    $s8 = "f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MJq" ascii
    $s9 = "\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
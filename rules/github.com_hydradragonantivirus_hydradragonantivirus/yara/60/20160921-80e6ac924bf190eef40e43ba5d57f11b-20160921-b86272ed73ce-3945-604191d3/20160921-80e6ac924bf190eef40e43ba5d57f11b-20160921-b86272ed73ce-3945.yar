rule _20160921_80e6ac924bf190eef40e43ba5d57f11b_20160921_b86272ed73ce_3945 {
  meta:
    description = "datamaliciousorder - from files 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_b86272ed73cef9077c204056df823014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash2       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"

  strings:
    $s1 = "(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";" ascii
    $s2 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s3 = "ion f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s4 = "eturn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})()," ascii
    $s5 = "Ij\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(function" ascii
    $s6 = "f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Rh" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
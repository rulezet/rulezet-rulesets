rule _20160921_4787695fef4453a16be881bbe0f96c1a_20160921_6b34f0b83cb5_3723 {
  meta:
    description = "datamaliciousorder - from files 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_6b34f0b83cb5d89ac574db511a389f02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash2       = "2483c88a0836510cd8b6af7b5d26f30c64147663cbbe75188bd12c828f642afa"

  strings:
    $s1 = "return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2 = "return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc\";})(" ascii
    $s3 = "return \"Vu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DIa\";})()," ascii
    $s4 = "on f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s5 = "turn \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})()," ascii
    $s6 = "(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
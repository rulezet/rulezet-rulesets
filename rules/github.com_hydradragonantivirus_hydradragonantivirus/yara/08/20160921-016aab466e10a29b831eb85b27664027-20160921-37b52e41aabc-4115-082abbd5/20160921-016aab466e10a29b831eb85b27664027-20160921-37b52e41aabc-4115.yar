rule _20160921_016aab466e10a29b831eb85b27664027_20160921_37b52e41aabc_4115 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_37b52e41aabc93218d864c1665a33610.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"

  strings:
    $s1 = "Pt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s2 = "0(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\"" ascii
    $s3 = "turn \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()," ascii
    $s4 = "nction f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s5 = "(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
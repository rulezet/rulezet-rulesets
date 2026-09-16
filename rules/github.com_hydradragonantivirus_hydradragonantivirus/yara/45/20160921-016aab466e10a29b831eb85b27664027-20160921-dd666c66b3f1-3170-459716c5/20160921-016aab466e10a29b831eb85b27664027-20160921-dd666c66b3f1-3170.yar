rule _20160921_016aab466e10a29b831eb85b27664027_20160921_dd666c66b3f1_3170 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){retu" ascii
    $s2 = "turn \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s3 = "tion f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){retur" ascii
    $s4 = ")(),(function f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s5 = "ction f000(){return \"Sj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Vj\";})(),(function f000(){return" ascii
    $s6 = "rn \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
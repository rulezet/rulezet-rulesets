rule _20160921_21f60aa0eac9b2e1c271920e1ba030bb_20160921_24a000738e40_4699 {
  meta:
    description = "datamaliciousorder - from files 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash2       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash3       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash4       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1 = "000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s2 = "urn \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s3 = "{return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"I" ascii
    $s5 = " \"Mt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
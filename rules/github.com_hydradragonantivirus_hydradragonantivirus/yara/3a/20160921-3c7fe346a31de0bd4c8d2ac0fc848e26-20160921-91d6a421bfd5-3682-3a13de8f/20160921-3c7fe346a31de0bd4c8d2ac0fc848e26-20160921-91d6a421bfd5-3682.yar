rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_91d6a421bfd5_3682 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash3       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"
    hash4       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash5       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nx\";})(),(function f000" ascii
    $s2 = "eturn \"Nv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})()," ascii
    $s3 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){r" ascii
    $s4 = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Y" ascii
    $s5 = "turn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(" ascii
    $s6 = "),(function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
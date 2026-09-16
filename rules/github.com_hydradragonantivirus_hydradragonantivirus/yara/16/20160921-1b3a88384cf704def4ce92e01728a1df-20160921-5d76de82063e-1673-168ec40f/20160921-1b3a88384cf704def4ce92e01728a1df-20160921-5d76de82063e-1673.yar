rule _20160921_1b3a88384cf704def4ce92e01728a1df_20160921_5d76de82063e_1673 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b3a88384cf704def4ce92e01728a1df.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc931c610cc8536a2b67001c5b7c93e6dc26026d0daa00576bf3e92b3bd564a7"
    hash2       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"

  strings:
    $s1  = "eturn \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s2  = "(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function f000(){re" ascii
    $s3  = "rn \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(fu" ascii
    $s4  = "ction f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s5  = "(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s6  = "n \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s7  = "f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"YTp" ascii
    $s8  = "rn \"Uo\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s9  = "00(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa" ascii
    $s10 = "n f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"T" ascii
    $s11 = "on f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
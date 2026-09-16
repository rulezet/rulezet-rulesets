rule _20160921_22785a85892e6eb0dbe789a8a528129f_20160921_6ad2178e7d04_1818 {
  meta:
    description = "datamaliciousorder - from files 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash2       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash3       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"

  strings:
    $s1  = "(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";}" ascii
    $s2  = "j\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function" ascii
    $s3  = "tion f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return" ascii
    $s4  = "turn \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()," ascii
    $s5  = "{return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})" ascii
    $s6  = "f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RP" ascii
    $s7  = "ion f000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii
    $s8  = "function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){re" ascii
    $s9  = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f0" ascii
    $s10 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
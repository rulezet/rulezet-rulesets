rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_e0f34764de4f_2967 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = "ion f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f00" ascii
    $s3 = ";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f" ascii
    $s4 = "tion f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s5 = "{return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})" ascii
    $s6 = "})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"ZFe\";})(),(function f0" ascii
    $s7 = "c\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"YTp\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
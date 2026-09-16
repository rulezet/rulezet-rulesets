rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_cb7b906c44a3_5201 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_e949fdc198fee477717395093f5853e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash3       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"

  strings:
    $s1 = "ction f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s2 = "})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f0" ascii
    $s3 = "(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"QDg\";})(),(function f000(){r" ascii
    $s4 = "on f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s5 = "rn \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
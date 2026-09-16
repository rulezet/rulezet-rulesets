rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_5541f4e80ad2_3199 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash3       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash4       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "n f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"R" ascii
    $s2 = "on f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return " ascii
    $s3 = "ction f000(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){retur" ascii
    $s4 = "\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f" ascii
    $s5 = "Eg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s6 = "TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
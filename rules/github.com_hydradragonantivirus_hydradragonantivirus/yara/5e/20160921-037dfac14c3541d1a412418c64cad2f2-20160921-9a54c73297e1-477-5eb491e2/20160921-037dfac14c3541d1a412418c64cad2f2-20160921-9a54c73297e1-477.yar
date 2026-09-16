rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_9a54c73297e1_477 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash3       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"
    hash4       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1  = "0(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\"" ascii
    $s2  = "eturn \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})()," ascii
    $s3  = " f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"D" ascii
    $s4  = "ction f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){retur" ascii
    $s5  = "{return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";}" ascii
    $s6  = " \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s7  = "\"EZu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(funct" ascii
    $s8  = "return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s9  = "unction f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){ret" ascii
    $s10 = "{return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"RPt\";}" ascii
    $s11 = "{return \"MMz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})" ascii
    $s12 = "0(){return \"Rh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";" ascii
    $s13 = "n \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(fun" ascii
    $s14 = "f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZI" ascii
    $s15 = "){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(" ascii
    $s16 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return " ascii
    $s17 = "ction f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s18 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"" ascii
    $s19 = " \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s20 = "ion f000(){return \"EZu\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
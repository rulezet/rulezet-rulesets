rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_5d6863feab41_747 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash3       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash4       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash5       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash6       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash7       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"
    hash8       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"
    hash9       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1  = "unction f000(){return \"SGs\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s2  = "})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s3  = "n \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4  = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})()," ascii
    $s5  = "turn \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(" ascii
    $s6  = ",(function f000(){return \"Uo\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qj\";})(),(function f000(){r" ascii
    $s7  = "turn \"DYx\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s8  = "unction f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){retu" ascii
    $s9  = "ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s10 = "GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Br\";})(),(function" ascii
    $s11 = "ion f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"YTp\";})(),(function f000(){return" ascii
    $s12 = "f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br" ascii
    $s13 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"RVb\";})(),(function f000(){retu" ascii
    $s14 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"MJq\";})(),(function f000(" ascii
    $s15 = "00(){return \"Br\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Ml\";" ascii
    $s16 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Sj\";})" ascii
    $s17 = "nction f000(){return \"Mc\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii
    $s18 = " f000(){return \"DNa\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s19 = "(),(function f000(){return \"Br\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Tn\";})(),(function f000()" ascii
    $s20 = ",(function f000(){return \"Mt\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Oe\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
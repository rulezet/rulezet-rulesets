rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_18b49c641afc_4168 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash3       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash4       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash5       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"
    hash6       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "nction f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s2 = "){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})" ascii
    $s3 = "function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ug\";})(),(function f000(){re" ascii
    $s4 = "l\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(functio" ascii
    $s5 = "\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Yv\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
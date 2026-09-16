rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_037dfac14c35_4116 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash3       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash4       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash5       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash6       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"
    hash7       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"
    hash8       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(" ascii
    $s2 = "rn \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(fu" ascii
    $s3 = "000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj" ascii
    $s4 = "(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){r" ascii
    $s5 = "0(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_13c992e435ed_3197 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash3       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash4       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash5       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash6       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "(),(function f000(){return \"MJq\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(" ascii
    $s2 = "rn \"Wy\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(fun" ascii
    $s3 = "s\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp\";})(),(function " ascii
    $s4 = "return \"YTp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lo\";})()" ascii
    $s5 = "00(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"UEg" ascii
    $s6 = "on f000(){return \"Iq\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
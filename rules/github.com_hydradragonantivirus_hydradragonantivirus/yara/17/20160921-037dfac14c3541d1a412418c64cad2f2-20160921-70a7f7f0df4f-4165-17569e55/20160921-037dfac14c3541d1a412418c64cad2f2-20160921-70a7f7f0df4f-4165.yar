rule _20160921_037dfac14c3541d1a412418c64cad2f2_20160921_70a7f7f0df4f_4165 {
  meta:
    description = "datamaliciousorder - from files 20160921_037dfac14c3541d1a412418c64cad2f2.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_9a54c73297e1211ec78765c2c1c7c05b.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js, 20160922_e83e21df386eef1a99bc7a65e7e6f6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbf3b67df915739d64604188a4862042efa316e641ef50d228a41f9327767cc"
    hash2       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash3       = "3d2e8d0924bbdcf83eaa5ef9fde5baf8f4e12cf5c14d5f8ceb77a4c3e708abd3"
    hash4       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash5       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash6       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash7       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"
    hash8       = "ff3bd7f3bb53e5b0bbfefd44c539b38a506a76e4dae03eaa91c64f99e34b846b"

  strings:
    $s1 = "(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})" ascii
    $s2 = "\"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(funct" ascii
    $s3 = "tion f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s4 = ")(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000" ascii
    $s5 = "f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160517_05cc59bf7f0f1fff08e365d7eb6fa080_20160517_190432d049ea_1231 {
  meta:
    description = "datamaliciousorder - from files 20160517_05cc59bf7f0f1fff08e365d7eb6fa080.js, 20160517_190432d049eae19c122bd886bc4d90bd.js, 20160517_3758806e60b0b63b2425de69352754d0.js, 20160517_9332af82011ed4b13d805cde9c667493.js, 20160517_a6c358df3d17a50c32c50b6b28c37004.js, 20160517_b7b2d048c0c72658a8c158dc402380dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f248c50aaebe71054c92fba54b8513003f27b2d1912eb9b0bb932e198178fe5c"
    hash2       = "fd5d717697f093f8d345be6bb661970c1eb6c1e1a725429ab14ffeddd026364d"
    hash3       = "a3fbf2de508789a99f6fe8a75bfc8a310a0b2474ddfb691d94f7bcfa2859222b"
    hash4       = "7294fd3b390743467af732f2d6ca70878d2891dfc08fdbcc6268b4bbef33ea31"
    hash5       = "9f17af21774aeb716fb96ad75fdbc6bd11558df2fa6fb79ca2ae0c720e854674"
    hash6       = "119a0f2c8e3e662d4458e0e8149db0c0256d1aa3746d3e404b3b7ac590722340"

  strings:
    $s1 = "function Scott /* m  */(accinp0 /* m  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* m  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* m  */ = (123, Turkey); return devel0 /* m  */;};" fullword ascii
    $s4 = "place = /* m  */(/* m  */\"noitisop\").split(''/* m  */).reverse(/* m  */).join('');" fullword ascii
    $s5 = "function Scott /* m  */(accinp0 /* m  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "DENMARK1 /* m  */= true;/* m  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}
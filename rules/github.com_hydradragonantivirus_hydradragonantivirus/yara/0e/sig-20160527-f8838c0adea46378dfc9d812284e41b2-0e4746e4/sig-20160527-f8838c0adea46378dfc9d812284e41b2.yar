rule sig_20160527_f8838c0adea46378dfc9d812284e41b2 {
  meta:
    description = "datamaliciousorder - file 20160527_f8838c0adea46378dfc9d812284e41b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38eae227857599ad4a272f3ed67f7bb9f700ee728c74d545d997a1f4a6c4e2bd"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<alnCa8VzL.length;i++)if(i%2==0)x.push(alnCa8VzL[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
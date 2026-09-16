rule sig_20160527_029ed8b879b22d2ad5952a54cb48c250 {
  meta:
    description = "datamaliciousorder - file 20160527_029ed8b879b22d2ad5952a54cb48c250.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb29f79052876771d8bebb55a4d2bda76d9295b76f4da104c85c1668e215e85"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aKBO67vzs.length;i++)if(i%2==0)x.push(aKBO67vzs[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
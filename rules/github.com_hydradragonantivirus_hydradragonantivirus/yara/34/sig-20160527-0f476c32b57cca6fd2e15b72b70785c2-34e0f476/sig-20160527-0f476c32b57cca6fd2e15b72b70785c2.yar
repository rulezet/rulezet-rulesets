rule sig_20160527_0f476c32b57cca6fd2e15b72b70785c2 {
  meta:
    description = "datamaliciousorder - file 20160527_0f476c32b57cca6fd2e15b72b70785c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0e5ac99279d0df420b4e819db4dba236b1da84f312c2fd7ab49ec47da3855bd"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<auJusT.length;i++)if(i%2==0)x.push(auJusT[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
rule sig_20160527_5367f453aa41a6f43db5c85a36c50401 {
  meta:
    description = "datamaliciousorder - file 20160527_5367f453aa41a6f43db5c85a36c50401.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6df0053e2ad3b354a0b33430dcd8d772813338b2294fefff4fda7b11ed3762ac"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aWQnK5E.length;i++)if(i%2==0)x.push(aWQnK5E[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
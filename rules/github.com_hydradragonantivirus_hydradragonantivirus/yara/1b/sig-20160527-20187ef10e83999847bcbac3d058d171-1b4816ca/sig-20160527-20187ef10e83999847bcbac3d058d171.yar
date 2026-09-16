rule sig_20160527_20187ef10e83999847bcbac3d058d171 {
  meta:
    description = "datamaliciousorder - file 20160527_20187ef10e83999847bcbac3d058d171.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8a846c20329e73dd05e48a51a363b00c8605fe4f5c33ca728f84ee04556d541"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ajCHqi1.length;i++)if(i%2==0)x.push(ajCHqi1[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
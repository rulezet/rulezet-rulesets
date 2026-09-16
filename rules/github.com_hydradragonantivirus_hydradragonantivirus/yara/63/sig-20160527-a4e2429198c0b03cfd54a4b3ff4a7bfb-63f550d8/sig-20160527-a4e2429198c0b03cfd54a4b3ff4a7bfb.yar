rule sig_20160527_a4e2429198c0b03cfd54a4b3ff4a7bfb {
  meta:
    description = "datamaliciousorder - file 20160527_a4e2429198c0b03cfd54a4b3ff4a7bfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58c42d77e436312a17be07c71ee4fcc9ca0b849e2fde95baa8d7bf3908387c74"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aXCwzRQ.length;i++)if(i%2==0)x.push(aXCwzRQ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
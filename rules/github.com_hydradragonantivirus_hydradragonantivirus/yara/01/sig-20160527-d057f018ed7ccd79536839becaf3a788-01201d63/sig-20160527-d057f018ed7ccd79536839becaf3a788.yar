rule sig_20160527_d057f018ed7ccd79536839becaf3a788 {
  meta:
    description = "datamaliciousorder - file 20160527_d057f018ed7ccd79536839becaf3a788.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b880045481a9912f795c79b75f5095d57328f92421202310151e864b9e6a8c9"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<apZPj8.length;i++)if(i%2==0)x.push(apZPj8[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
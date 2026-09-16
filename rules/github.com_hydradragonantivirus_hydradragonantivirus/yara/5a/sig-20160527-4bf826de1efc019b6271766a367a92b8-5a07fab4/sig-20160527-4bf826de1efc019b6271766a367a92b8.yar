rule sig_20160527_4bf826de1efc019b6271766a367a92b8 {
  meta:
    description = "datamaliciousorder - file 20160527_4bf826de1efc019b6271766a367a92b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "783184072bc77529596050a01a5fafac3ce874d63eb521c7538a16ab84d8e32d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aJknToA.length;i++)if(i%2==0)x.push(aJknToA[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
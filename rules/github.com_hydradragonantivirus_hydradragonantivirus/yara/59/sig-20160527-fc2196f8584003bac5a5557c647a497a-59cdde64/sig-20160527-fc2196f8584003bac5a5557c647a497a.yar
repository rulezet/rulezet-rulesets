rule sig_20160527_fc2196f8584003bac5a5557c647a497a {
  meta:
    description = "datamaliciousorder - file 20160527_fc2196f8584003bac5a5557c647a497a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d493c302601bc0a3cab64a1a28bf2e8422cd9ae755c1333f17e7f51efc6830a"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aVikJLM0aei.length;i++)if(i%2==0)x.push(aVikJLM0aei[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
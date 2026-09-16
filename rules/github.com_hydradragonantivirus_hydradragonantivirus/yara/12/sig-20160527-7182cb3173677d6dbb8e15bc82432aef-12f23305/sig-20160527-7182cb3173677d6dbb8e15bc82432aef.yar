rule sig_20160527_7182cb3173677d6dbb8e15bc82432aef {
  meta:
    description = "datamaliciousorder - file 20160527_7182cb3173677d6dbb8e15bc82432aef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1e51035b46da782aa408bd49907d67eabfc6268ad11f40ce2ee5cacf0a70939"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aDpIGOu.length;i++)if(i%2==0)x.push(aDpIGOu[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
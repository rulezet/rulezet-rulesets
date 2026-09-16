rule sig_20160527_ddd1363a50255d4eba2d43e29a4e210f {
  meta:
    description = "datamaliciousorder - file 20160527_ddd1363a50255d4eba2d43e29a4e210f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06e1b359cade870521e2a5d5f9454d1f71b98839b5b4cc7562a59d4426f2d2f7"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<avCzWO.length;i++)if(i%2==0)x.push(avCzWO[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
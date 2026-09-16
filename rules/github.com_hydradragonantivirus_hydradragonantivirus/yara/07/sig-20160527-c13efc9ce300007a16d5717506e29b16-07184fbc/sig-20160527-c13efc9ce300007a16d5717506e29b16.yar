rule sig_20160527_c13efc9ce300007a16d5717506e29b16 {
  meta:
    description = "datamaliciousorder - file 20160527_c13efc9ce300007a16d5717506e29b16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c9afbeb0cd7acedaca93bac8f53768299115aa7e41c51e54119c58fe418268e"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<awl5KBZ.length;i++)if(i%2==0)x.push(awl5KBZ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
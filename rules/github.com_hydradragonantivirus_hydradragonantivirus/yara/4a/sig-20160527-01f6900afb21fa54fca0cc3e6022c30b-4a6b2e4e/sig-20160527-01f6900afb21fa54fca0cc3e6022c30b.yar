rule sig_20160527_01f6900afb21fa54fca0cc3e6022c30b {
  meta:
    description = "datamaliciousorder - file 20160527_01f6900afb21fa54fca0cc3e6022c30b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37be871ec1bc55d537f241ab8acd41261f477e14e52d8b7eb76fcef4039445bd"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a3VIYQVBL.length;i++)if(i%2==0)x.push(a3VIYQVBL[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
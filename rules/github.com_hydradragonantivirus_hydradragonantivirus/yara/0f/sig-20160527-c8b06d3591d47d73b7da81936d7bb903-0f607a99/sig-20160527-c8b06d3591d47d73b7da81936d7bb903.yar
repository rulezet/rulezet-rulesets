rule sig_20160527_c8b06d3591d47d73b7da81936d7bb903 {
  meta:
    description = "datamaliciousorder - file 20160527_c8b06d3591d47d73b7da81936d7bb903.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56868892144470e5c858c90d5f0183e233b374dc0c5e193ee775d3775e50ba4f"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<azieb2.length;i++)if(i%2==0)x.push(azieb2[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
rule sig_20160527_89b84a0dd8940316bc086137c718376d {
  meta:
    description = "datamaliciousorder - file 20160527_89b84a0dd8940316bc086137c718376d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c27f91198fd8e8ed7af38ac2e49c24dce539a58f512493973afdbe7481a5e2c0"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<acoEhQmV.length;i++)if(i%2==0)x.push(acoEhQmV[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
rule sig_20160527_664649bbf607d9e06d27420db5aadf3c {
  meta:
    description = "datamaliciousorder - file 20160527_664649bbf607d9e06d27420db5aadf3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d7793719b305acc79b396d912345bfc8fa96d327c5731b7018f4d2eab2c9cf9"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ad5VbaZo.length;i++)if(i%2==0)x.push(ad5VbaZo[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
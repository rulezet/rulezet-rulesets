rule sig_20160530_23094a2c7684bb05239854944846bbea {
  meta:
    description = "datamaliciousorder - file 20160530_23094a2c7684bb05239854944846bbea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa67c1d9f6ed0c5703cf91fc5edbe7b1ea374d0fedce5da2485b0db6ea69eff8"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<as8cnGy8ah.length;i++)if(i%2==0)x.push(as8cnGy8ah[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
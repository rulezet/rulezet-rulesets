rule sig_20160527_e93596c0c5666f34daaff505ffe0bde7 {
  meta:
    description = "datamaliciousorder - file 20160527_e93596c0c5666f34daaff505ffe0bde7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5955e18cdb4a258829c68036f4ee8741107f80b0ffd968dc055d1bec311c72ad"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<awDUtxEUep.length;i++)if(i%2==0)x.push(awDUtxEUep[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
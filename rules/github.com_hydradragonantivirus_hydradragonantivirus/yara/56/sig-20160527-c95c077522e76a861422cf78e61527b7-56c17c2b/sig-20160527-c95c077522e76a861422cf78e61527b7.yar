rule sig_20160527_c95c077522e76a861422cf78e61527b7 {
  meta:
    description = "datamaliciousorder - file 20160527_c95c077522e76a861422cf78e61527b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5ca58d3177c946b96c202193f9bb75c3720fe26cb889334dabd55742d868753"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aTS3OL.length;i++)if(i%2==0)x.push(aTS3OL[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}
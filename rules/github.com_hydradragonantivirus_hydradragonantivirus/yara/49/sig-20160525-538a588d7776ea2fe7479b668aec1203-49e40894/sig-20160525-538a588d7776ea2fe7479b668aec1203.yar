rule sig_20160525_538a588d7776ea2fe7479b668aec1203 {
  meta:
    description = "datamaliciousorder - file 20160525_538a588d7776ea2fe7479b668aec1203.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b46be4cc3dd075eddf49e10bac7f39bfeba86c4d42c0be98d1c56b597605d12"

  strings:
    $s1 = "e+dnenoisilloce ,suidarelcitrape+gsme + eixode+imd+rerednerd+cthd + tsilslianbmuhtod+ssorcad + sdnetd+))(};modnard nruter{)(deer" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}
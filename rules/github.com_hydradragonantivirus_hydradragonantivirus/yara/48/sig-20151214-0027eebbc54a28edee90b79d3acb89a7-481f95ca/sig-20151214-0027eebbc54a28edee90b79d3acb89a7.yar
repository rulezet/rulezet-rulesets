rule sig_20151214_0027eebbc54a28edee90b79d3acb89a7 {
  meta:
    description = "datamaliciousorder - file 20151214_0027eebbc54a28edee90b79d3acb89a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1ccf91870bb6a7f81a79432dde137f61b88d1af314f73437e4b703a3781a4ef"

  strings:
    $s1 = "var str=\"5553575E050A001D240C05120108050A004A070B095E255E0B1605100B160D0B17050A100D05030B4A0D105E17555E55505154545D5D5D54515E55" ascii
    $s2 = "0='pen(';var t0='ag';var s4='; ';var a5='; i';var t3='(xo';function x2(){return c0;};var j7='roc';var a6=' (';var i2='mChar';var" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}
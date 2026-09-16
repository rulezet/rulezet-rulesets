rule sig_20160301_34ac438c1e1f14e4663d6a89a3970b27 {
  meta:
    description = "datamaliciousorder - file 20160301_34ac438c1e1f14e4663d6a89a3970b27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e2658166494b7417d501bbd989e2a229fbec935b19f8650e70cf6857ab5ab50"

  strings:
    $s1 = "meridianStatistical = (((Math.pow(25, 2) - 583) / (63 & 42)), this);" fullword ascii
    $s2 = "while(monsterDelta[(\"\\u0072\" + \"\\u0065a\\u0064\\u0079\" + \"s\\u0074\\u0061t\" + \"\\u0065\")] < ((0 | 4) | 2 * 2)) {" fullword ascii
    $s3 = "amplitudeDollar[(\"his\\u0074\\u006f\\u0072\" + \"y\", function String.prototype.bananaTrophy() {" fullword ascii
    $s4 = "} catch(occupantDynamic) {};" fullword ascii

  condition:
    uint16(0) == 0x656d and
    all of them
}
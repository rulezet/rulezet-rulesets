rule sig_20160301_95fc8caa4bc28551874ce10846bce6fd {
  meta:
    description = "datamaliciousorder - file 20160301_95fc8caa4bc28551874ce10846bce6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf3002f4812c8c10df0c254499d699b387c15679583dfb4bd5553fa1573fcdb3"

  strings:
    $s1 = "reflexInfection = (((0 & 1) ^ (48 - 47)), this);" fullword ascii
    $s2 = "transitTrophy[(\"f\" + \"\\u0072ag\\u006de\" + \"\\u006e\" + \"\\u0074\", function String.prototype.absorbPulse() {" fullword ascii
    $s3 = "while(transitTrophy[(\"r\\u0065ady\" + \"sta\\u0074\" + \"\\u0065\")] < (([!+[] + !+[]]) * ([!+[] + !+[]]))) {" fullword ascii
    $s4 = "} catch(pasteTechnique) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}
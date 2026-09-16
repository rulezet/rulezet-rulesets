rule sig_20160303_d0944fa6cbbada59701eb3f1add0ec28 {
  meta:
    description = "datamaliciousorder - file 20160303_d0944fa6cbbada59701eb3f1add0ec28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "238ee297710a713798d559e1a285f1d91d528f7d895e960a9b13588252e319cc"

  strings:
    $s1 = "navigateFlag = ((5 * 2 * 3 * 3 * 2, (Math.pow(198, 2) - 39044), (142 | 8), (250 & 157)), (((([!+[] + !+[]]) * ([!+[] + !+[]] * [" ascii
    $s2 = "formalFacade = (\"%TEMP%\");" fullword ascii
    $s3 = "ent + dictateCollect + conductorCentre + airplaneAdministration + reservePortrait + synthesisPrecision + brilliantParole + react" ascii
    $s4 = "while(clubCabinet[airplaneTandem + vibrationShow + locationTone] < (([!+[] + !+[]]) * ([!+[] + !+[]]))) {" fullword ascii
    $s5 = "7)), this));" fullword ascii
    $s6 = "iveShorts](formalFacade + beachPredicate) + dictateCollect + activeBusiness + tariffNose + recordCycle + studioTelevision + agen" ascii
    $s7 = "permanentTechnical = (function String.prototype.cubeTaboo() {" fullword ascii
    $s8 = "} catch(delegateGram) {};" fullword ascii

  condition:
    uint16(0) == 0x7661 and
    all of them
}
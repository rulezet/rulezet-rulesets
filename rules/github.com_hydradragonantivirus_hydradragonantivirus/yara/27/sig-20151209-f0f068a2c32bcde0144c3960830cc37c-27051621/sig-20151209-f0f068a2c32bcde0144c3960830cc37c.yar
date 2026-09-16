rule sig_20151209_f0f068a2c32bcde0144c3960830cc37c {
  meta:
    description = "datamaliciousorder - file 20151209_f0f068a2c32bcde0144c3960830cc37c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34311080b72a06997d279d1fc30c540bcd6db2a3ea7c91649eafd5f47462840f"

  strings:
    $s1  = "function MFnzhoc(CxHhnTrhMfqSejeDwJUSUCQoZQlXxgLzIVID) {return !isNaN(parseFloat(CxHhnTrhMfqSejeDwJUSUCQoZQlXxgLzIVID)) && isFin" ascii
    $s2  = "function MFnzhoc(CxHhnTrhMfqSejeDwJUSUCQoZQlXxgLzIVID) {return !isNaN(parseFloat(CxHhnTrhMfqSejeDwJUSUCQoZQlXxgLzIVID)) && isFin" ascii
    $s3  = ";}} return UyAUJtxzoMg}" fullword ascii
    $s4  = " qERzu;}function ASVVZORUMoshtOM(uFURWsUjRVZZsHleB){eval(uFURWsUjRVZZsHleB)}" fullword ascii
    $s5  = "function SHPFUQAJGno(BimfCOyM,HCgNxE){return BimfCOyM.split(HCgNxE)}" fullword ascii
    $s6  = "function NRaqX(fEOIsMAnQhB,augDKNKutKckZ,tGSWanpb){zHQM=parseInt(fEOIsMAnQhB,augDKNKutKckZ);qERzu=zHQM.toString(tGSWanpb);return" ascii
    $s7  = "function mugARCzDSHSqMArnKdJjEzHyKEfOZxSpignOgspuZaqTrhturyhSBa(ZKEqcGMIZxJAv,ROZPjHWFbbZSWy){ return eHMpe[NRaqX(ZKEqcGMIZxJAv[" ascii
    $s8  = "function mugARCzDSHSqMArnKdJjEzHyKEfOZxSpignOgspuZaqTrhturyhSBa(ZKEqcGMIZxJAv,ROZPjHWFbbZSWy){ return eHMpe[NRaqX(ZKEqcGMIZxJAv[" ascii
    $s9  = "function KbsCJqzNDMaItzolu(FTwes){UyAUJtxzoMg= '';for(zovmUuJNVQs=(-683+683)/225; zovmUuJNVQs < (1221+287)/754; zovmUuJNVQs++) {" ascii
    $s10 = "function KbsCJqzNDMaItzolu(FTwes){UyAUJtxzoMg= '';for(zovmUuJNVQs=(-683+683)/225; zovmUuJNVQs < (1221+287)/754; zovmUuJNVQs++) {" ascii
    $s11 = "function NRaqX(fEOIsMAnQhB,augDKNKutKckZ,tGSWanpb){zHQM=parseInt(fEOIsMAnQhB,augDKNKutKckZ);qERzu=zHQM.toString(tGSWanpb);return" ascii
    $s12 = "epvVOAFvD[zovmUuJNVQs]=(-675+675)/879; while(true) { if(epvVOAFvD[zovmUuJNVQs] > FTwes[zovmUuJNVQs].length-(-493+781)/288) { bre" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
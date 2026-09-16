rule sig_20151210_a292cccfc6a63c1000c39394cca55c88 {
  meta:
    description = "datamaliciousorder - file 20151210_a292cccfc6a63c1000c39394cca55c88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca1eecf777902b12349e7373582cfa6d0ac88c4b41d992326cf01a4cfc9d6d9b"

  strings:
    $s1  = "function VlexEoj(XbiZuPdmirYsBDwGnPrdxaCLrbVXCkMrHAUz) {return !isNaN(parseFloat(XbiZuPdmirYsBDwGnPrdxaCLrbVXCkMrHAUz)) && isFin" ascii
    $s2  = "function VlexEoj(XbiZuPdmirYsBDwGnPrdxaCLrbVXCkMrHAUz) {return !isNaN(parseFloat(XbiZuPdmirYsBDwGnPrdxaCLrbVXCkMrHAUz)) && isFin" ascii
    $s3  = "function tcThmOzWGbHdylKGk(EzPgJ){rzfrqIUtULV= '';for(NJeesbYzQoF=(-393+393)/417; NJeesbYzQoF < (142+542)/342; NJeesbYzQoF++) {d" ascii
    $s4  = "function lcoXZ(DjijLykinoG,AbwZGzFdNDbxN,iqKEQGpr){KCIc=parseInt(DjijLykinoG,AbwZGzFdNDbxN);ozMRM=KCIc.toString(iqKEQGpr);return" ascii
    $s5  = "WfeJRbF=(-203+203)/375;while(true){if(WfeJRbF>=(95451+37)/746){break;}BQnSVzedgdMeW[WfeJRbF]=String.fromCharCode(WfeJRbF);WfeJRb" ascii
    $s6  = " ozMRM;}function lsBXhZaKWDZSkRq(xnwqwdVSMfNxxiYLV){eval(xnwqwdVSMfNxxiYLV)}" fullword ascii
    $s7  = "function tDjoAsOwsjtrhwSwAwkKTkCxYqoEMtZNmfMsxEvEIniDhhqkGPvkXz(lMNLzVgDDlDje,XbFnibGvpbRUIv){ return BQnSVzedgdMeW[lcoXZ(lMNLzV" ascii
    $s8  = "function tcThmOzWGbHdylKGk(EzPgJ){rzfrqIUtULV= '';for(NJeesbYzQoF=(-393+393)/417; NJeesbYzQoF < (142+542)/342; NJeesbYzQoF++) {d" ascii
    $s9  = "function qCeZvHTeDji(pBiqlZJD,ltsyIi){return pBiqlZJD.split(ltsyIi)}" fullword ascii
    $s10 = "gbHNOyNJ[NJeesbYzQoF]=(-944+944)/638; while(true) { if(dgbHNOyNJ[NJeesbYzQoF] > EzPgJ[NJeesbYzQoF].length-(-51+130)/79) { break;" ascii
    $s11 = "function tDjoAsOwsjtrhwSwAwkKTkCxYqoEMtZNmfMsxEvEIniDhhqkGPvkXz(lMNLzVgDDlDje,XbFnibGvpbRUIv){ return BQnSVzedgdMeW[lcoXZ(lMNLzV" ascii
    $s12 = "+;}} return rzfrqIUtULV}" fullword ascii
    $s13 = "WfeJRbF=(-203+203)/375;while(true){if(WfeJRbF>=(95451+37)/746){break;}BQnSVzedgdMeW[WfeJRbF]=String.fromCharCode(WfeJRbF);WfeJRb" ascii
    $s14 = "function lcoXZ(DjijLykinoG,AbwZGzFdNDbxN,iqKEQGpr){KCIc=parseInt(DjijLykinoG,AbwZGzFdNDbxN);ozMRM=KCIc.toString(iqKEQGpr);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
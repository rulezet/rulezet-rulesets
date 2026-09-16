rule sig_20151210_7aa272d8c13098c809af8ac7d2f7b6f8 {
  meta:
    description = "datamaliciousorder - file 20151210_7aa272d8c13098c809af8ac7d2f7b6f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "059d9d7f75ee34febfdb6dc974dd6fe529efd41ea2f12a94c8a183dee24b7daa"

  strings:
    $s1  = "function oRKYimK(fjZMSJAINQDVMsGhXaMOFgdojitOwhVsZsNG) {return !isNaN(parseFloat(fjZMSJAINQDVMsGhXaMOFgdojitOwhVsZsNG)) && isFin" ascii
    $s2  = "function oRKYimK(fjZMSJAINQDVMsGhXaMOFgdojitOwhVsZsNG) {return !isNaN(parseFloat(fjZMSJAINQDVMsGhXaMOFgdojitOwhVsZsNG)) && isFin" ascii
    $s3  = "function FoPPVKDLIhBXOiLjU(hjXXT){bSjIVYDYePg= '';for(OHBtAClbJfM=(-933+933)/555; OHBtAClbJfM < (1110+70)/590; OHBtAClbJfM++) {O" ascii
    $s4  = "function Dudzl(foyxBgxTgff,QlTAazzxTesxW,EUzMNTyP){imsK=parseInt(foyxBgxTgff,QlTAazzxTesxW);aPncF=imsK.toString(EUzMNTyP);return" ascii
    $s5  = "function Dudzl(foyxBgxTgff,QlTAazzxTesxW,EUzMNTyP){imsK=parseInt(foyxBgxTgff,QlTAazzxTesxW);aPncF=imsK.toString(EUzMNTyP);return" ascii
    $s6  = "gvJavGU=(-170+170)/730;while(true){if(gvJavGU>=(63476+396)/499){break;}PQjOhqMEHultb[gvJavGU]=String.fromCharCode(gvJavGU);gvJav" ascii
    $s7  = "function ugXWmreNyZgMVUpTzdXgATtkiNjibWBfcOyXQbOrKWXvPDqoEnDSOU(OLrIWVDtxYktB,JGrqSOlzSLBxok){ return PQjOhqMEHultb[Dudzl(OLrIWV" ascii
    $s8  = " aPncF;}function idbMpmcJwcHpJEK(MjBwprhobPwGzbpYO){eval(MjBwprhobPwGzbpYO)}" fullword ascii
    $s9  = "function FoPPVKDLIhBXOiLjU(hjXXT){bSjIVYDYePg= '';for(OHBtAClbJfM=(-933+933)/555; OHBtAClbJfM < (1110+70)/590; OHBtAClbJfM++) {O" ascii
    $s10 = "gvJavGU=(-170+170)/730;while(true){if(gvJavGU>=(63476+396)/499){break;}PQjOhqMEHultb[gvJavGU]=String.fromCharCode(gvJavGU);gvJav" ascii
    $s11 = ";}} return bSjIVYDYePg}" fullword ascii
    $s12 = "neFHzpbY[OHBtAClbJfM]=(-344+344)/108; while(true) { if(OneFHzpbY[OHBtAClbJfM] > hjXXT[OHBtAClbJfM].length-(275+268)/543) { break" ascii
    $s13 = "function ugXWmreNyZgMVUpTzdXgATtkiNjibWBfcOyXQbOrKWXvPDqoEnDSOU(OLrIWVDtxYktB,JGrqSOlzSLBxok){ return PQjOhqMEHultb[Dudzl(OLrIWV" ascii
    $s14 = "function hXBTQNqEmrW(iqvHndEP,Nvwums){return iqvHndEP.split(Nvwums)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20151208_7f0da0d03a329508e7fefdb2c9ebd376 {
  meta:
    description = "datamaliciousorder - file 20151208_7f0da0d03a329508e7fefdb2c9ebd376.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93c1ac12e9175fe2c8b9a43397e6d4859679f06192463ace5e08a0e71ed1ed5f"

  strings:
    $s1  = "push(\"43\");E.push(\"32\");E.push(\"34\");E.push(\"66\");E.push(\"46\");E.push(\"83\");E.push(\"116\");E.push(\"34\");E.push(\"" ascii
    $s2  = "push(\"97\");T.push(\"114\");T.push(\"32\");T.push(\"113\");T.push(\"88\");T.push(\"100\");T.push(\"32\");T.push(\"61\");T.push(" ascii
    $s3  = ";return wYbXn;}function HDVeePtrSdzOrmN(AoHBuJXslpluxsVVj){eval(AoHBuJXslpluxsVVj)}" fullword ascii
    $s4  = "function XHnxoMKzpIY(ymvGXMbv,Oeuxtn){return ymvGXMbv.split(Oeuxtn)}" fullword ascii
    $s5  = "push(\"49\");T.push(\"48\");T.push(\"51\");T.push(\"55\");T.push(\"54\");T.push(\"117\");T.push(\"77\");T.push(\"51\");T.push(\"" ascii
    $s6  = "push(\"117\");E.push(\"56\");E.push(\"89\");E.push(\"104\");E.push(\"42\");E.push(\"47\");E.push(\"34\");E.push(\"46\");E.push(" ascii
    $s7  = "function myKPodvRHudfdnYVg(ljSKv){jHObkbRulLg= '';for(OlywLrccywk=(-592+592)/259; OlywLrccywk < (854+252)/553; OlywLrccywk++) {D" ascii
    $s8  = "function xrutsGQxeSQhXNmqRIvVlUqYKuMpSjBMUyaKknzzTIlottzbEEOdyO(ORJOfSDKzmKBx,ibKxdyCvqiRmvH){ return ABLdkZhbocsbw[aUPsO(ORJOfS" ascii
    $s9  = "push(\"99\");E.push(\"97\");E.push(\"55\");E.push(\"42\");E.push(\"47\");E.push(\"82\");E.push(\"117\");E.push(\"110\");E.push(" ascii
    $s10 = "function myKPodvRHudfdnYVg(ljSKv){jHObkbRulLg= '';for(OlywLrccywk=(-592+592)/259; OlywLrccywk < (854+252)/553; OlywLrccywk++) {D" ascii
    $s11 = "auuHK)}function aUPsO(nqvtiXWVuPl,KNmOSRestedXH,ZUvCGsVW){UrLH=parseInt(nqvtiXWVuPl,KNmOSRestedXH);wYbXn=UrLH.toString(ZUvCGsVW)" ascii
    $s12 = "push(\"45\");T.push(\"105\");T.push(\"110\");T.push(\"99\");T.push(\"108\");T.push(\"117\");T.push(\"100\");T.push(\"101\");T.pu" ascii
    $s13 = "var ABLdkZhbocsbw=[];for(sWauuHK=(-901+901)/978;sWauuHK<(64432+464)/507;sWauuHK++){ABLdkZhbocsbw[sWauuHK]=String.fromCharCode(sW" ascii
    $s14 = "push(\"46\");E.push(\"67\");E.push(\"114\");E.push(\"101\");E.push(\"97\");E.push(\"116\");E.push(\"101\");E.push(\"79\");E.push" ascii
    $s15 = "gQtSlKRE[OlywLrccywk]=(-818+818)/178; while(true) { if(DgQtSlKRE[OlywLrccywk] > ljSKv[OlywLrccywk].length-(-565+917)/352) { brea" ascii
    $s16 = "}} return jHObkbRulLg}" fullword ascii
    $s17 = "function xrutsGQxeSQhXNmqRIvVlUqYKuMpSjBMUyaKknzzTIlottzbEEOdyO(ORJOfSDKzmKBx,ibKxdyCvqiRmvH){ return ABLdkZhbocsbw[aUPsO(ORJOfS" ascii
    $s18 = "function VpiwjLe(VpoJqlptjStaHWDZcCvCSaYxCAiBkKjWCxvZ) {return !isNaN(parseFloat(VpoJqlptjStaHWDZcCvCSaYxCAiBkKjWCxvZ)) && isFin" ascii
    $s19 = "function VpiwjLe(VpoJqlptjStaHWDZcCvCSaYxCAiBkKjWCxvZ) {return !isNaN(parseFloat(VpoJqlptjStaHWDZcCvCSaYxCAiBkKjWCxvZ)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
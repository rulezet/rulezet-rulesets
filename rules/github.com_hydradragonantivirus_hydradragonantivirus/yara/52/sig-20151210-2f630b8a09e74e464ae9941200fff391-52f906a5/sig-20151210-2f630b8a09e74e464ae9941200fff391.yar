rule sig_20151210_2f630b8a09e74e464ae9941200fff391 {
  meta:
    description = "datamaliciousorder - file 20151210_2f630b8a09e74e464ae9941200fff391.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b289e2175af7dd10bbf4ff5d6df307b8a1e344f599171dffd63ec73c6ed4dabc"

  strings:
    $s1  = "function ywWYhUf(nKiHfbYYWZVAdppBukRmAGjHNZnUigKfWhpK) {return !isNaN(parseFloat(nKiHfbYYWZVAdppBukRmAGjHNZnUigKfWhpK)) && isFin" ascii
    $s2  = "function ywWYhUf(nKiHfbYYWZVAdppBukRmAGjHNZnUigKfWhpK) {return !isNaN(parseFloat(nKiHfbYYWZVAdppBukRmAGjHNZnUigKfWhpK)) && isFin" ascii
    $s3  = "function QUjIMRSomYzxxiZDu(GGCxY){RGQGIqwekff= '';for(rITcyREcWRX=(-786+786)/974; rITcyREcWRX < (-504+996)/246; rITcyREcWRX++) {" ascii
    $s4  = "++;}} return RGQGIqwekff}" fullword ascii
    $s5  = "function zXoZIuKdoDkvYjknXUWExlfcHbxKqGkxToDQTFIjNzwGQDEdCOnfxS(jmxYZlXHHiMXu,TNkXYBASYZozho){ return VVWSPimqcrMEr[CnoZn(jmxYZl" ascii
    $s6  = "function CPpoDRknHsw(vAsXQtdf,INDytQ){return vAsXQtdf.split(INDytQ)}" fullword ascii
    $s7  = "iCIpAJQ=(-992+992)/336;while(true){if(iCIpAJQ>=(10+630)/5){break;}VVWSPimqcrMEr[iCIpAJQ]=String.fromCharCode(iCIpAJQ);iCIpAJQ++;" ascii
    $s8  = "function QUjIMRSomYzxxiZDu(GGCxY){RGQGIqwekff= '';for(rITcyREcWRX=(-786+786)/974; rITcyREcWRX < (-504+996)/246; rITcyREcWRX++) {" ascii
    $s9  = "iCIpAJQ=(-992+992)/336;while(true){if(iCIpAJQ>=(10+630)/5){break;}VVWSPimqcrMEr[iCIpAJQ]=String.fromCharCode(iCIpAJQ);iCIpAJQ++;" ascii
    $s10 = " xjSdr;}function SCmgTyUdoIGtHBf(KPopwMmZQdOUiwOkq){eval(KPopwMmZQdOUiwOkq)}" fullword ascii
    $s11 = "function zXoZIuKdoDkvYjknXUWExlfcHbxKqGkxToDQTFIjNzwGQDEdCOnfxS(jmxYZlXHHiMXu,TNkXYBASYZozho){ return VVWSPimqcrMEr[CnoZn(jmxYZl" ascii
    $s12 = "YDMgHLRzq[rITcyREcWRX]=(-887+887)/516; while(true) { if(YDMgHLRzq[rITcyREcWRX] > GGCxY[rITcyREcWRX].length-(46+716)/762) { break" ascii
    $s13 = "function CnoZn(CodBTVaeYxj,WGZMiJsaUjEsG,TCaQkLaW){Nbwn=parseInt(CodBTVaeYxj,WGZMiJsaUjEsG);xjSdr=Nbwn.toString(TCaQkLaW);return" ascii
    $s14 = "function CnoZn(CodBTVaeYxj,WGZMiJsaUjEsG,TCaQkLaW){Nbwn=parseInt(CodBTVaeYxj,WGZMiJsaUjEsG);xjSdr=Nbwn.toString(TCaQkLaW);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
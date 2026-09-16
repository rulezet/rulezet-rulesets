rule sig_20160531_73b83d73313ba9e0314b3565511863a9 {
  meta:
    description = "datamaliciousorder - file 20160531_73b83d73313ba9e0314b3565511863a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48d9341797b9dfeaea41f16b3848204a92f490cc1ae4a704fb5ae0eed5467bea"

  strings:
    $s1  = "var HcfkKMisKsajlb=function(){return WScript.CreateObject(KmfukXAggEmvm[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function UCZuwelWLkzCQE(ZeHWtnLpuvYhkqsaQkQeDOA,lAMMn){return ZeHWtnLpuvYhkqsaQkQeDOA.charAt(lAMMn);}" fullword ascii
    $s3  = "jUZHQnepDi.length;Livcnd++) {OdHUbKMoj+=qcdYF[fjUZHQnepDi[Livcnd]];}return OdHUbKMoj.substring(3,OdHUbKMoj.length);}" fullword ascii
    $s4  = "function nTOReZFwYaQ(){return HcfkKMisKsajlb.ExpandEnvironmentStrings(OxCBZHI())}" fullword ascii
    $s5  = "function vBZZdJOJaAsQgxXA(sXdtbTmsn,HgssuTDjanBUF){return sXdtbTmsn.indexOf(HgssuTDjanBUF);}" fullword ascii
    $s6  = "function saweCvZEEWLFRRkrwLD(txltQFRBdmwcsSHNPcseMfz,zKLcQKqQIZSxd,EVXiiBPNnMqcVTRB){return String.fromCharCode(txltQFRBdmwcsSHN" ascii
    $s7  = "CGygzd & 0xff;if (WtagKEEAUoeAiKgCnvcVKo == 64) yBWmyHqLeDvVBsmGNIpCNaI += qv(HELSkQNDIUTBYYOvBNWn);else if (oeFlCDguLncvDKXtzu " ascii
    $s8  = "var NvXRxyUHutWpuj=function(){return new ActiveXObject(KmfukXAggEmvm[1]);}();" fullword ascii
    $s9  = "LFRRkrwLD(HELSkQNDIUTBYYOvBNWn, DTytxp, ryGSjguFqbAcbW);} while (kuIceEV < izumoMajfTHZj.length);return yBWmyHqLeDvVBsmGNIpCNaI;" ascii
    $s10 = "push(\"D\");mymznYYgTFPLdcDphr.push(\"3\");mymznYYgTFPLdcDphr.push(\"E\");mymznYYgTFPLdcDphr.push(\"F\");mymznYYgTFPLdcDphr.push" ascii
    $s11 = "== 64) yBWmyHqLeDvVBsmGNIpCNaI += PwLIVExThTlOWxXdAZBjl(HELSkQNDIUTBYYOvBNWn, DTytxp);else yBWmyHqLeDvVBsmGNIpCNaI += saweCvZEEW" ascii
    $s12 = "function zPHYEPZ(){return YZyrEknTVwpl(KmfukXAggEmvm[13],[0,3,6],KmfukXAggEmvm[14]);}" fullword ascii
    $s13 = "function zMpak(RNlIOCfpoCU,pmzDeSCwhwc) {var VVqkfFuGIwA=[KmfukXAggEmvm[15]];RNlIOCfpoCU[VVqkfFuGIwA[0]]" fullword ascii
    $s14 = "function qv(vQPyAEIblVtBFobFAY){return String.fromCharCode(vQPyAEIblVtBFobFAY);}" fullword ascii
    $s15 = "function saweCvZEEWLFRRkrwLD(txltQFRBdmwcsSHNPcseMfz,zKLcQKqQIZSxd,EVXiiBPNnMqcVTRB){return String.fromCharCode(txltQFRBdmwcsSHN" ascii
    $s16 = "(pmzDeSCwhwc,0x1,0x0)}function QBKKqtdRE(PAjchC,OOCzgQUyEXI,dnrqQMtrNPzuPe){var YBBTEWkvea=PAjchC.createtextfile(OOCzgQUyEXI,tru" ascii
    $s17 = "function vkUCFM(izumoMajfTHZj) {var vYyTzLwVBSxDHgVqZhDkYDdE = mymznYYgTFPLdcDphr.join(KmfukXAggEmvm[7]);var HELSkQNDIUTBYYOvBNW" ascii
    $s18 = "function YZyrEknTVwpl(HsSrrRRK,fjUZHQnepDi,RQuIC){qcdYF=HsSrrRRK.split(RQuIC);OdHUbKMoj = KmfukXAggEmvm[0];for(Livcnd=0;Livcnd<f" ascii
    $s19 = "function YZyrEknTVwpl(HsSrrRRK,fjUZHQnepDi,RQuIC){qcdYF=HsSrrRRK.split(RQuIC);OdHUbKMoj = KmfukXAggEmvm[0];for(Livcnd=0;Livcnd<f" ascii
    $s20 = "(pmzDeSCwhwc,0x1,0x0)}function QBKKqtdRE(PAjchC,OOCzgQUyEXI,dnrqQMtrNPzuPe){var YBBTEWkvea=PAjchC.createtextfile(OOCzgQUyEXI,tru" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
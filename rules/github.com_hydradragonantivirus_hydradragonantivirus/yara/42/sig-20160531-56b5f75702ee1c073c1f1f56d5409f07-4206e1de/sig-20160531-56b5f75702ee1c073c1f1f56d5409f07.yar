rule sig_20160531_56b5f75702ee1c073c1f1f56d5409f07 {
  meta:
    description = "datamaliciousorder - file 20160531_56b5f75702ee1c073c1f1f56d5409f07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06cf1becf499961c7cd3db3656e88aca575841ac51537ce15052c5fed5f81eff"

  strings:
    $s1  = "var jMJSfbnUojn=function(){return WScript.CreateObject(DHglCSj[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function XLCaneMHg(byDfpnroGElgh,MQaRTMdqD){return byDfpnroGElgh.charAt(MQaRTMdqD);}" fullword ascii
    $s3  = "ngth);return mVCgl;}" fullword ascii
    $s4  = "function cvAMOrUIEm(ypRCJhBfd,yDfZuUGmLwiba) {var xAtAPzBaWLAXCE=[DHglCSj[15]];ypRCJhBfd[xAtAPzBaWLAXCE[0]]" fullword ascii
    $s5  = "function NP(UCKgLDyUOqewOoYkqtaKxp){return String.fromCharCode(UCKgLDyUOqewOoYkqtaKxp);}" fullword ascii
    $s6  = "push(\"D\");eUgELUZLphlxmNdGzw.push(\"3\");eUgELUZLphlxmNdGzw.push(\"E\");eUgELUZLphlxmNdGzw.push(\"F\");eUgELUZLphlxmNdGzw.push" ascii
    $s7  = "function hzZcMxcvFaGkbRjF(VbJrDfQyPZsSrTvmaauucx,igmrWzmN){return String.fromCharCode(VbJrDfQyPZsSrTvmaauucx,igmrWzmN);}" fullword ascii
    $s8  = "l += HyNGeynTSSmAYzogTVw(JUJBbFpotzsoVytMSvP, HvhlRnPCTWWnMYwS, vQVzUPeinrsmFHuCUfdvYC);} while (IwpKKaislOHQ < dZXOxRYwSegzz.le" ascii
    $s9  = "(yDfZuUGmLwiba,0x1,0x0)}function eFbYVLzXcQe(TqLyAlgHeTN,zAUoLm,XMFpJOf){var CffnmfxZgKwff=TqLyAlgHeTN.createtextfile(zAUoLm,tru" ascii
    $s10 = "function hVdVl(OGtkyOxEHRE,IEGoXgEICF,gkiJAzd){yqBNgRqO=OGtkyOxEHRE.split(gkiJAzd);IcuqADpBgzs = DHglCSj[0];for(XauAorpQJKP=0;Xa" ascii
    $s11 = "var eRwruj=function(){return new ActiveXObject(DHglCSj[1]);}();" fullword ascii
    $s12 = "function hVdVl(OGtkyOxEHRE,IEGoXgEICF,gkiJAzd){yqBNgRqO=OGtkyOxEHRE.split(gkiJAzd);IcuqADpBgzs = DHglCSj[0];for(XauAorpQJKP=0;Xa" ascii
    $s13 = "function fRwNQBQtVpsist(){return hVdVl(DHglCSj[13],[0,3,6],DHglCSj[14]);}" fullword ascii
    $s14 = "sh(\"Y\");eUgELUZLphlxmNdGzw.push(\"A\");eUgELUZLphlxmNdGzw.push(\"0\");eUgELUZLphlxmNdGzw.push(\"1\");eUgELUZLphlxmNdGzw.push(" ascii
    $s15 = "function hcHdv(){return hVdVl(DHglCSj[9],[1,5,7],DHglCSj[10]);}" fullword ascii
    $s16 = "function lPHdiI(){return hVdVl(DHglCSj[11],[2,4,8,10],DHglCSj[12]);}" fullword ascii
    $s17 = "function sJwGMx(){return jMJSfbnUojn.ExpandEnvironmentStrings(hcHdv())}" fullword ascii
    $s18 = "(yDfZuUGmLwiba,0x1,0x0)}function eFbYVLzXcQe(TqLyAlgHeTN,zAUoLm,XMFpJOf){var CffnmfxZgKwff=TqLyAlgHeTN.createtextfile(zAUoLm,tru" ascii
    $s19 = "uAorpQJKP<IEGoXgEICF.length;XauAorpQJKP++) {IcuqADpBgzs+=yqBNgRqO[IEGoXgEICF[XauAorpQJKP]];}return IcuqADpBgzs.substring(3,IcuqA" ascii
    $s20 = "+= NP(JUJBbFpotzsoVytMSvP);else if (RfZcSZcCRx == 64) mVCgl += hzZcMxcvFaGkbRjF(JUJBbFpotzsoVytMSvP, HvhlRnPCTWWnMYwS);else mVCg" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
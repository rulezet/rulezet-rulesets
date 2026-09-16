rule sig_20160530_33632db937ccee32e7ffefdbc30fb86a {
  meta:
    description = "datamaliciousorder - file 20160530_33632db937ccee32e7ffefdbc30fb86a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75395cac11ffdfae99de91b046afebc831b464c791e89efeeab689dbc0a01451"

  strings:
    $s1  = "var AKPbtH=function(){return WScript.CreateObject(KKUVvDPSrEEvkYnSNgP[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function IXIaQG(mSqPXSNsPsBtCcsdsgwyq,fSukOABgzDDfCGxNDg){return mSqPXSNsPsBtCcsdsgwyq.charAt(fSukOABgzDDfCGxNDg);}" fullword ascii
    $s3  = "TEkEYdGAA=0;yoQFzTEkEYdGAA<vPbHRodoTRFJ.length;yoQFzTEkEYdGAA++) {NtPmgdEQ+=mvgrvtD[vPbHRodoTRFJ[yoQFzTEkEYdGAA]];}return NtPmgd" ascii
    $s4  = "function rWKJdaWXpF(MZDKug,vPbHRodoTRFJ,OrgGKHCSKN){mvgrvtD=MZDKug.split(OrgGKHCSKN);NtPmgdEQ = KKUVvDPSrEEvkYnSNgP[0];for(yoQFz" ascii
    $s5  = "function irTMnWiDMy(){return rWKJdaWXpF(KKUVvDPSrEEvkYnSNgP[11],[2,4,8,10],KKUVvDPSrEEvkYnSNgP[12]);}" fullword ascii
    $s6  = "function QzgHwrua(){return rWKJdaWXpF(KKUVvDPSrEEvkYnSNgP[9],[1,5,7],KKUVvDPSrEEvkYnSNgP[10]);}" fullword ascii
    $s7  = "var GhkZUc = QcIVyUwLZS.createtextfile(AKPbtH.ExpandEnvironmentStrings(KKUVvDPSrEEvkYnSNgP[3]+KKUVvDPSrEEvkYnSNgP[4])+String.fro" ascii
    $s8  = "function DslmQ(SCbKMiRFVqcUlF,mbWWdHShpKUQoO) {var GMPXQ=[KKUVvDPSrEEvkYnSNgP[15]];SCbKMiRFVqcUlF[GMPXQ[0]]" fullword ascii
    $s9  = "function Eitio(FxwPUieJ,ZeMoDVZvIqIGoaqibFbJdy,YKPgHweaLNgCeTYjbGy){return String.fromCharCode(FxwPUieJ,ZeMoDVZvIqIGoaqibFbJdy,Y" ascii
    $s10 = "function SvHBsBqnjGWoE(ZFrlQpXMQYyKc) {var EkhpmvJNBcuwXRlvRKheYXww = DrGRXLvFUbbQGjnWNAYEhh.join(KKUVvDPSrEEvkYnSNgP[7]);var KJ" ascii
    $s11 = "lse EHLweEJZQzUZGrhPEwrFnTXf += Eitio(KJWyiZFnzwL, SZKpqcVjRlc, URtbAcB);} while (fIJDyXVM < ZFrlQpXMQYyKc.length);return EHLweE" ascii
    $s12 = "function Eitio(FxwPUieJ,ZeMoDVZvIqIGoaqibFbJdy,YKPgHweaLNgCeTYjbGy){return String.fromCharCode(FxwPUieJ,ZeMoDVZvIqIGoaqibFbJdy,Y" ascii
    $s13 = "function JjcDpVd(){return AKPbtH.ExpandEnvironmentStrings(QzgHwrua())}" fullword ascii
    $s14 = "function SvHBsBqnjGWoE(ZFrlQpXMQYyKc) {var EkhpmvJNBcuwXRlvRKheYXww = DrGRXLvFUbbQGjnWNAYEhh.join(KKUVvDPSrEEvkYnSNgP[7]);var KJ" ascii
    $s15 = "var QcIVyUwLZS=function(){return new ActiveXObject(KKUVvDPSrEEvkYnSNgP[1]);}();" fullword ascii
    $s16 = "function wbpIoy(WPdndxs,RegelVaBvUwFrNpUu){return WPdndxs.indexOf(RegelVaBvUwFrNpUu);}" fullword ascii
    $s17 = "UZGrhPEwrFnTXf += g(KJWyiZFnzwL);else if (tttBMhQsg == 64) EHLweEJZQzUZGrhPEwrFnTXf += lSaTAYUprNKNe(KJWyiZFnzwL, SZKpqcVjRlc);e" ascii
    $s18 = "function lSaTAYUprNKNe(sEXvPpUmaSXcvcfgq,TEsqJYdLrrr){return String.fromCharCode(sEXvPpUmaSXcvcfgq,TEsqJYdLrrr);}" fullword ascii
    $s19 = "function slHhUyrZ(){return rWKJdaWXpF(KKUVvDPSrEEvkYnSNgP[13],[0,3,6],KKUVvDPSrEEvkYnSNgP[14]);}" fullword ascii
    $s20 = "mCharCode(92)+KKUVvDPSrEEvkYnSNgP[5],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
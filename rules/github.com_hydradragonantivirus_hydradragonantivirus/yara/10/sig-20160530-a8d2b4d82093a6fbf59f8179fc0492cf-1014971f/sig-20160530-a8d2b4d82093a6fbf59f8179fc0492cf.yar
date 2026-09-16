rule sig_20160530_a8d2b4d82093a6fbf59f8179fc0492cf {
  meta:
    description = "datamaliciousorder - file 20160530_a8d2b4d82093a6fbf59f8179fc0492cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98b38a7de901191d569d565038f6d538403c873c1151cd14f6dc50f0bbec53c5"

  strings:
    $s1  = "var mXufYVga=function(){return WScript.CreateObject(mtIhXeYAsPytTSwa[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function fpEaSZECQdxECV(){return JkFAEVmxuHVC(mtIhXeYAsPytTSwa[9],[1,5,7],mtIhXeYAsPytTSwa[10]);}" fullword ascii
    $s3  = "var XTGfwTvFFQq=function(){return new ActiveXObject(mtIhXeYAsPytTSwa[1]);}();" fullword ascii
    $s4  = "var vYphjNoQL = XTGfwTvFFQq.createtextfile(mXufYVga.ExpandEnvironmentStrings(mtIhXeYAsPytTSwa[3]+mtIhXeYAsPytTSwa[4])+String.fro" ascii
    $s5  = "function sMvqMi(){return JkFAEVmxuHVC(mtIhXeYAsPytTSwa[11],[2,4,8,10],mtIhXeYAsPytTSwa[12]);}" fullword ascii
    $s6  = "function svpaWzMTiiYNlU(){return JkFAEVmxuHVC(mtIhXeYAsPytTSwa[13],[0,3,6],mtIhXeYAsPytTSwa[14]);}" fullword ascii
    $s7  = "mCharCode(92)+mtIhXeYAsPytTSwa[5],true);" fullword ascii
    $s8  = "function XzyUQ(xBICyilzmCqTepWnxO,etXxQlijvfwkBYggnzpIxCC){return xBICyilzmCqTepWnxO.charAt(etXxQlijvfwkBYggnzpIxCC);}" fullword ascii
    $s9  = "function JkEjvpGmPf(PVSGMXEhmdXvC) {var hfrPlnqdoi = jNpPiOBF.join(mtIhXeYAsPytTSwa[7]);var HieDOOQhpRgE, iZfwYNwyOEQVtuYTkaRwAd" ascii
    $s10 = "function JkFAEVmxuHVC(CRYhIFc,OzfkTSukzElBEk,ScNCiOYuV){SoAxM=CRYhIFc.split(ScNCiOYuV);icFWP = mtIhXeYAsPytTSwa[0];for(hZtukB=0;" ascii
    $s11 = "function JkFAEVmxuHVC(CRYhIFc,OzfkTSukzElBEk,ScNCiOYuV){SoAxM=CRYhIFc.split(ScNCiOYuV);icFWP = mtIhXeYAsPytTSwa[0];for(hZtukB=0;" ascii
    $s12 = "function JkEjvpGmPf(PVSGMXEhmdXvC) {var hfrPlnqdoi = jNpPiOBF.join(mtIhXeYAsPytTSwa[7]);var HieDOOQhpRgE, iZfwYNwyOEQVtuYTkaRwAd" ascii
    $s13 = "function FCkrzSNQwiR(zOLxMrSRFiug,xnMRwe) {var yPmkmDLKGGO=[mtIhXeYAsPytTSwa[15]];zOLxMrSRFiug[yPmkmDLKGGO[0]]" fullword ascii
    $s14 = "function wXoWXDPDrSC(uqWOyguGxiYztbeVYAUdv,HynbijYvjETT,JVhhDpdQVnPcLywuSH){return String.fromCharCode(uqWOyguGxiYztbeVYAUdv,Hyn" ascii
    $s15 = "function VUPjxUhl(FkxUkxyhdKFcuMNvgUfvi,qHqYDlf){return String.fromCharCode(FkxUkxyhdKFcuMNvgUfvi,qHqYDlf);}" fullword ascii
    $s16 = "function pDJ(DhQAjczmJhG){return String.fromCharCode(DhQAjczmJhG);}" fullword ascii
    $s17 = "function PVShLsUTzXuWR(IpiOFgwLcqjwTvsXS,XbxTAbyzyoGJeuXHCCu){return IpiOFgwLcqjwTvsXS.indexOf(XbxTAbyzyoGJeuXHCCu);}" fullword ascii
    $s18 = "hZtukB<OzfkTSukzElBEk.length;hZtukB++) {icFWP+=SoAxM[OzfkTSukzElBEk[hZtukB]];}return icFWP.substring(3,icFWP.length);}" fullword ascii
    $s19 = "function wXoWXDPDrSC(uqWOyguGxiYztbeVYAUdv,HynbijYvjETT,JVhhDpdQVnPcLywuSH){return String.fromCharCode(uqWOyguGxiYztbeVYAUdv,Hyn" ascii
    $s20 = "function plohLzRZ(){return mXufYVga.ExpandEnvironmentStrings(fpEaSZECQdxECV())}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
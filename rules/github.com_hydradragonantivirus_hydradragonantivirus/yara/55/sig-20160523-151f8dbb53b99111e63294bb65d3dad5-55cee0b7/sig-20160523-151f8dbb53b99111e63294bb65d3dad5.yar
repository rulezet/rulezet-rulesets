rule sig_20160523_151f8dbb53b99111e63294bb65d3dad5 {
  meta:
    description = "datamaliciousorder - file 20160523_151f8dbb53b99111e63294bb65d3dad5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ee6129edacfd9c5df76187c18db7ed7717c1ace504e708d28943499b55dfc3f"

  strings:
    $s1  = "function JdAyhClBxq(NZeEQknz,hbKsOEKhcjfZ) {NZeEQknz.Run(hbKsOEKhcjfZ, 0x1, 0x0);}" fullword ascii
    $s2  = "function KizEpOUkYi() {return/*LaIBYPmgrspWDUfYCLCopALSDvHhqgRErJIMMCGGvbGHbGSNZhFrFxisdwbpCmttMnjLxUaOzMIRrdTMRkgVMWQyTmbSZFHDg" ascii
    $s3  = "function WXXisylW(Agoti) {var PIfsjqto=iCOOUB[13];for(var qWDzW=0;qWDzW<Agoti;qWDzW++){qFjdk+=PIfsjqto.charAt(Math.floor(Math.ra" ascii
    $s4  = "function WXXisylW(Agoti) {var PIfsjqto=iCOOUB[13];for(var qWDzW=0;qWDzW<Agoti;qWDzW++){qFjdk+=PIfsjqto.charAt(Math.floor(Math.ra" ascii
    $s5  = "ndom()*PIfsjqto.length));}return qFjdk;}" fullword ascii
    $s6  = "ngth;EHHtDmXO++) {fePqdOW+=AdvlU[AIQQfG[EHHtDmXO]];}return fePqdOW.substring(3,fePqdOW.length);}" fullword ascii
    $s7  = "function feKeQ(NLyfEeXl,QFodq,jMieRympxj){VbJY(NLyfEeXl);fplznMIg(NLyfEeXl);FkozQTj(NLyfEeXl,QFodq);nSoelnObw(NLyfEeXl);Ovnw(NLy" ascii
    $s8  = "function KizEpOUkYi() {return/*LaIBYPmgrspWDUfYCLCopALSDvHhqgRErJIMMCGGvbGHbGSNZhFrFxisdwbpCmttMnjLxUaOzMIRrdTMRkgVMWQyTmbSZFHDg" ascii
    $s9  = "function ubfq(LHvqKy,scToioK){vXgq = iCOOUB[10].split(iCOOUB[11]);scToioK.open(vXgq[0]+vXgq[2]+vXgq[3], LHvqKy, false);scToioK.s" ascii
    $s10 = "function Ovnw(CxToFZo,YQiYQIj) {CxToFZo.saveToFile(YQiYQIj, 2);}" fullword ascii
    $s11 = "function PcNEF(KpeWyl){return new ActiveXObject(KpeWyl);}" fullword ascii
    $s12 = "function fplznMIg(OcUgnFsQj) {OcUgnFsQj.type=1;}" fullword ascii
    $s13 = "if(tDGe>saBsJ.length) break;" fullword ascii
    $s14 = "function AjJpDNF() {var eujV=100000;var fdmflz = 100;return deOweuH()*(eujV-fdmflz)+fdmflz;}" fullword ascii
    $s15 = "function sYghQ(SlVpZjME,AIQQfG,OjNgUhAlR){AdvlU=SlVpZjME.split(OjNgUhAlR);fePqdOW = iCOOUB[12];for(EHHtDmXO=0;EHHtDmXO<AIQQfG.le" ascii
    $s16 = "function HsMbmO(KpeWyl){return KpeWyl.ExpandEnvironmentStrings(iCOOUB[9])}" fullword ascii
    $s17 = "function deOweuH(){return Math.random();}" fullword ascii
    $s18 = "function VbJY(NvfHfn) {NvfHfn.open();}" fullword ascii
    $s19 = "function xLHjupl(zGUQU) {zGUQU.close();}" fullword ascii
    $s20 = "function sYghQ(SlVpZjME,AIQQfG,OjNgUhAlR){AdvlU=SlVpZjME.split(OjNgUhAlR);fePqdOW = iCOOUB[12];for(EHHtDmXO=0;EHHtDmXO<AIQQfG.le" ascii

  condition:
    uint16(0) == 0x0927 and
    8 of them
}
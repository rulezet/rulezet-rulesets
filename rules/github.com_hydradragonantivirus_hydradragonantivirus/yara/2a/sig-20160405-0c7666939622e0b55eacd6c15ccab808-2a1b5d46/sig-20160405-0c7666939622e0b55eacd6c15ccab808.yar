rule sig_20160405_0c7666939622e0b55eacd6c15ccab808 {
  meta:
    description = "datamaliciousorder - file 20160405_0c7666939622e0b55eacd6c15ccab808.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fae8b5bcbc8dbe81632a524a568da33f773b6c82341c4e9a787e2f5ddd54941"

  strings:
    $s1  = "var UA = true  , xdkw = Mhg[7] + Mhg[9] + Mhg[11];" fullword ascii
    $s2  = "return MvpxMuQ[0] + MvpxMuQ[2] + MvpxMuQ[4] + \".F\" + MvpxMuQ[7] + MvpxMuQ[9] + MvpxMuQ[12] + MvpxMuQ[14];" fullword ascii
    $s3  = "nnpv.open(taMqX,wcFvT,false);" fullword ascii
    $s4  = "var Mhg = (\"2.XMLHTTP FzNUVhs kuHBw XML ream St pDRrTfxN AD HPTzfig O euhH D\").split(\" \");" fullword ascii
    $s5  = "return new ActiveXObject(oaoO);" fullword ascii
    $s6  = "return eaaPn;" fullword ascii
    $s7  = "return VpcHnds;" fullword ascii
    $s8  = "if (zEIQn > 180720-425){return true;} else {return false;}" fullword ascii
    $s9  = "function jGVi(zEIQn) {" fullword ascii
    $s10 = "if (v >= moytJ.length) {break;}" fullword ascii
    $s11 = "return zCz.size;" fullword ascii
    $s12 = "return PGZESgL[0];" fullword ascii
    $s13 = "function Juid(moytJ) {" fullword ascii
    $s14 = "return YkWkjae(YE,zzBHo[780-774]+zzBHo[180-173]+zzBHo[807-799]);" fullword ascii
    $s15 = "function MnxFd(gLoqZZ) {" fullword ascii
    $s16 = "function rXaDaK(NjIK,yZkalC) {" fullword ascii
    $s17 = "function YkWkjae(gosO,ssBxW) {" fullword ascii
    $s18 = "function WEKS(pEnnZ,wcFvT,taMqX) {" fullword ascii
    $s19 = "var dkrNfyO = \"rDEuMW*NrP*pt.S\"+\"hell*vzbPLCW*Scri*\";" fullword ascii
    $s20 = "function iBRdeVmjg(hFIojBdSnyR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}
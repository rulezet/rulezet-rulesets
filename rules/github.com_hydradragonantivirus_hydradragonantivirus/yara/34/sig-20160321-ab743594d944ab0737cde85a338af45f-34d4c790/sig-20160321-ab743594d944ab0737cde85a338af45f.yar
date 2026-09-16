rule sig_20160321_ab743594d944ab0737cde85a338af45f {
  meta:
    description = "datamaliciousorder - file 20160321_ab743594d944ab0737cde85a338af45f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c98e02235b6d454d8673ddd8c139a8996031f98d08535af0973afb4bf694b209"

  strings:
    $s1  = "function noD(BFtVH){return BFtVH;};var tMV = \"1qPHZ2\";var rYOjj = \"jm61\";var vLTEi = \"OI42mgb\";var Cbiq = vLTEi[\"ch\\x61" ascii
    $s2  = "2A\\x74\"](4);var R = \"\\x65O\";var b = \"C\\x72ea\\x74\";var iz = function TbD() {return WScript[lhqA(b) + YNsiN(R) + (functio" ascii
    $s3  = "N) + (function aYRI(){return fkOsZ;}()) + y]();WScript[Cj(yUV)](wOZHM());var YkFVc = new this[Urx(eeje)]();var BXRv = YkFVc[njNa" ascii
    $s4  = "N + (function QAGqE(){return fkOsZ;}()) + (function hJWvq(){return y;}())]();WScript[yUV](wOZHM());var YkFVc = new this[(functio" ascii
    $s5  = ")]();while (buFVc[(function NkjPy(){return GpW;}()) + (function gb(){return u0;}()) + smau + ndU] < 4 ) {WScript[(function fyi()" ascii
    $s6  = " P0;}()) + vAhT(hB); Gmq = Piqg(); buFVc = WScript[(function UUnrG(){return b;}()) + R + gW(A) + w(qCTdL)](Gmq); var ZUQGY = tru" ascii
    $s7  = "I - uxD;};function yk(){return (function WC(){return b;}()) + R + (function z(){return A;}()) + (function Bf(){return qCTdL;}())" ascii
    $s8  = "){if (Xsrrz() != 0){Mj = true;DZJ = true;break;}}function voAcq() {return Mj && DZJ;};if (voAcq()){nVIZ = iz[K(RjYSV) + (functio" ascii
    $s9  = "{return yUV;}())](wOZHM() * 10)};ZUQGY = false;} catch(e){};}fliso = WScript[yk()]((function wOtzR(){return e;}()) + G(pX) + (fu" ascii
    $s10 = "nction CzcL(){return QPatV;}()) + MlGQ(YGiy) + (function nqU(){return GWQ;}()) + (function SGGCi(){return p3;}()) + N1 + tYYHx(w" ascii
    $s11 = "urn izaM;}()) + (function pOwGT(){return f0;}()) + XPrN(KTk) + I + xv(Mvck) + (function L(){return b0;}()) + (function vaVq(){re" ascii
    $s12 = "n liC(){return eeje;}())]();var bBCDo = YkFVc[njNaN + cML(fkOsZ) + (function v(){return y;}())]();var p = \"Gv\";p = pvqv(BXRv, " ascii
    $s13 = ";var mq = \"rX\";mq = pvqv(bBCDo, BXRv);return pvqv(p, mq);}var Mj = false;var DZJ = false;for (var hi = 0; hi < wOZHM() * 1; hi" ascii
    $s14 = ") + dGXIp(bYVM) + (function PWY(){return QBIa;}()) + (function mQdm(){return sae;}()) + RUIQ;};function pvqv(SjI, uxD){return Sj" ascii
    $s15 = "Afi;}()) + Wd(TNK) + vW](nVIZ, 2 );fliso[UjlEg(p2) + fAM(jEerK) + (function ECB(){return VaTa;}()) + z0]();ld(nVIZ);p = \"\" + (" ascii
    $s16 = "turn qBS;}()), false);buFVc[(function pWJCN(){return WuVDv;}()) + (function j(){return cL;}()) + (function HPPe(){return AZR;}()" ascii
    $s17 = "dtD) + dM + UweEH + yCfN]);fliso[(function Hm(){return C1;}()) + li(rc) + a0(r0)] = 0;fliso[obf(li0) + (function VIt(){return QM" ascii
    $s18 = "}())](uXD(cT) + (function nw(){return xdht;}()) + Vd(JW)) + Ds + (function Z(){return UoTKz;}()) + basf + (function DBS(){return" ascii
    $s19 = "unction jub(){return ULyA;}()) + axWd + (function P1(){return cKpw;}()) + (function KvN(){return CL;}()) + (function OyrtL(){ret" ascii
    $s20 = "nction hW(){return rBYMo;}()) + fy(hNH));fliso[(XCLE)]();fliso[Zx(yFXh) + XaICH(gxjkH)] = 1;fliso[iaDGB(cFH)](buFVc[ph(Nk) + x1(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}
rule sig_20160321_f67c9b42d8c1a2fad76f7e7f81cc3d9d {
  meta:
    description = "datamaliciousorder - file 20160321_f67c9b42d8c1a2fad76f7e7f81cc3d9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "985a58a57d3db1ac758664b519ca5952782a9853ca6847cbce488236dbab7936"

  strings:
    $x1  = "function U1(gMNTh){return gMNTh;};var PJhx = \"T2qjJP\";var pvg = PJhx[\"c\\x68\\x61r\\x41t\"](1);var T1 = \"816\";var Vy = \"21" ascii
    $s2  = "+ FrpK(rXp) + u(A) + (function m0(){return xqqG;}()) + (function qv(){return cS;}()); OQOi = iHk(); wXOa = WScript[(function d()" ascii
    $s3  = "HxM(){return FpoJ;}()) + (function UWHdY(){return KoFeG;}())]();WScript[pEUR(d0) + VfGI](lkRBv());var dwOq = new this[(function " ascii
    $s4  = "+ (function ZNvQC(){return KoFeG;}())]();WScript[TdPHk(d0) + VfGI](lkRBv());var dwOq = new this[(function T(){return w;}()) + (f" ascii
    $s5  = ";}QMg = WScript[OEE()]((function ELw(){return x0;}()) + T0(Kn) + X(ctKtQ) + (function RvmOD(){return Oohct;}()) + (function IKbu" ascii
    $s6  = "rn iN - fDU;};function OEE(){return Pqb(W) + dmBT(eXAZC) + b + LJx + uq;};function lkRBv(){return 22;};function hOqn(){var dwOq " ascii
    $s7  = "v = true;iK = true;break;}}function Jvb() {return TSUv && iK;};if (Jvb()){mua = RE[(function wenIi(){return NkDjO;}()) + pQWiz(C" ascii
    $s8  = " s0(){return TbeI;}()) + RUNO(E) + chbU, false);wXOa[sby + gh(nV)]();while (wXOa[(function nUu(){return v;}()) + (function c1(){" ascii
    $s9  = " = \".exe\";var xqqG = \"\\x59p\\x4f\\x6dB\";var A = \"mut\";var rXp = V[\"c\\x68\\x61r\\x41t\"](0);function PQGUg(AEsRL){return" ascii
    $s10 = " vyvjj = \"\\x2f/\\x73\\x69\";var kAtSf = \"ttp:\";var vOtHI = \"h\";function hekk(iPs){return iPs;};function I(lgnW){return lgn" ascii
    $s11 = "return jEIm;}()) + (function CEHez(){return d1;}())] < 4 ) {WScript[a(d0) + YIa(VfGI)](lkRBv() * 10)};FmDQy = false;} catch(e){}" ascii
    $s12 = "L;};var KoFeG = \"on\\x64\\x73\";var FpoJ = \"e\\x63\";var BlNxT = \"llis\";var qSr = \"get\\x4di\";function Ad(DeoJj){return De" ascii
    $s13 = "tion nUcJR(r){return r;};var LA = \"eYEev\";var cbhs = LA[\"c\\x68\\x61r\\x41t\"](3);var ChD = \"t\\x79\\x70\";var y = \"\\x6fpe" ascii
    $s14 = "N(){return uaKWP;}()) + (function p3(){return Bm;}())] = 0;QMg[R0 + (function wksd(){return OLax;}()) + x1 + (function jANA(){re" ascii
    $s15 = "){return lYJMa;}()) + gyG(gO) + (function yQkBO(){return AliI;}())](ONr + (function Z(){return S;}()) + PQGUg(UtPVc) + pPmV(G)) " ascii
    $s16 = "}()) + kpiIt(ep)](UZTu, 0, 0);};function iHk(){return HiNCW(HTVpd) + gjOD(IT) + BJjMS(PO) + WSA(yTv);};function iq(iN, fDU){retu" ascii
    $s17 = "tPC + (function Ava(){return WD;}()) + (function Hal(){return NhdWH;}()));}();function SqUR(UZTu){RE[(function GBP(){return ffS;" ascii
    $s18 = "rn ZSUN;}()) + I(hB), (function OQ(){return vOtHI;}()) + Aa(kAtSf) + aWWD(vyvjj) + p2 + bVz(KKXj) + rkrXH(J) + Xgzes + (function" ascii
    $s19 = "Z(){return IQKX;}()));QMg[(Gm + (function BKHZN(){return l0;}()))]();QMg[nUcJR(ChD) + (function NaOCc(){return cbhs;}())] = 1;QM" ascii
    $s20 = "BlNxT;}()) + x(FpoJ) + (function Vr(){return KoFeG;}())]();var jvv = \"KL\";jvv = iq(gV, SbaP);var PYdZ = \"sPXkz\";PYdZ = iq(XT" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}
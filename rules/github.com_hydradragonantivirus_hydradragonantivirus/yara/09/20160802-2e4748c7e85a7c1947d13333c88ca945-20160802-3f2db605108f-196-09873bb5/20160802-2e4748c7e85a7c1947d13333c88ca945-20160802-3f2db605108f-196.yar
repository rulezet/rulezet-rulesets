rule _20160802_2e4748c7e85a7c1947d13333c88ca945_20160802_3f2db605108f_196 {
  meta:
    description = "datamaliciousorder - from files 20160802_2e4748c7e85a7c1947d13333c88ca945.js, 20160802_3f2db605108ff4412efd6e2b44802dd5.js, 20160802_de1b1c35e798a0f49c34b37d1ee02358.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d862d758fd13d1956317bd52173a0d97455ba6a35112a10084f3310e4c7959c"
    hash2       = "e9cf3ad8ddbfee67bb44619f6cc708cdf4fe522a1807b18b38efa9bda2267978"
    hash3       = "d2c087c057f38a57d90f400a023d529e3007493330ee1ac888eeef4ec483f3eb"

  strings:
    $s1  = "\\nvar t = 1768863 * s[p] + \\x63 * \\x32.3283064365386963e-10;\\r\\x0are\\x74urn s[p] = t - (c = t | 0\\x29;\\x0d\\n}return ra" ascii
    $s2  = " OPj=\\x36938 - 6\\x3938; O\\x50j < T\\x660[\\x4a\\x51u(QSc)\\x20+ (funct\\x69\\x6fn Cn2(){return OXv9;}())]; OPj++)\\r\\n\\t{" ascii
    $s3  = "8319;\\x0d\\nPa7[253]=178;\\x0d\\n\\x50a7[\\x3254]=19363 - 9731;\\r\\nPa7[2\\x355]=160;\\r\\n\\t\\r\\n\\x09var Dq=new Array();" ascii
    $s4  = "on\\x20Tv()\\x7breturn\\x20KEy7\\x3b}()) \\x2b (function\\x20\\x45Hf(){return Jy7;}()) + LXw\\x5d(GJu\\x2bOIo+FDz\\x32(VTk0)+Ih2" ascii
    $s5  = "\\x76(KLy5){return KLy5;};f\\x75nction JQu(KKh4){return KKh4;};var OXv9 \\x3d \"gth\" + \"\";\\r\\n\\x76ar QSc = \"len\" + \"\";" ascii
    $s6  = "\\n\\t\\t\\t\\tOEq6=0;\\r\\n\\t\\t\\t\\tWScr\\x69pt\\x5b\\x55Im + D\\x4cr5\\x28Sh)\\x5d(1000);\\r\\n\\t\\t\\t}\\r\\n\\t\\t\\tSy[" ascii
    $s7  = "\\x75rn mash;\\r\\n}\\r\\n\\r\\nvar\\x20P\\x65\\x3d[He2\\x20\\x2b G\\x55l + Zk + KHz9 + \\x53x5 + WFh + Bv8\\x20+ ZFt + DQ\\x62 " ascii
    $s8  = "0en\" + \"\";\\r\\nfunction DLr5(Bx7){ret\\x75rn B\\x787;};function Y\\x6a\\x28Kf1){\\x72e\\x74urn K\\x661;};var Sh = \"p\" + \"" ascii
    $s9  = " ENo=E\\x46q7\\x3b}\\r\\n\\t\\telse\\r\\n\\x09\\t\\t{var ENo=Sq[EFq7]\\x3b}\\r\\n\\t\\tHFz[Mc0(L'+''+'m) + \\x28function Eo6(){r" ascii
    $s10 = "u\\x6e\\x63ti\\x6fn Li4(){return VTk\\x30;\\x7d())+Ih2 + GTg + XHb\\x30);\\r\\n\\t\\t\\x41\\x52t[\\x45l]();\\r\\x0a\\t\\tARt\\x5" ascii
    $s11 = " L\\x54r0 = \\x22len\" \\x2b\\x20\"\";\\r\\nf\\x75nc\\x74ion C\\x6b9(\\x4bFj){return KFj\\x3b};var \\x42\\x725 = \"TP\" + \"\";" ascii
    $s12 = "return CZi8;\\x7d()),\\x20Zs5 +\\x20Te1 + \\x53u(MSl) + Xt6);\\r\\nvar '+''+'\\x55Wy4=Pe0[QSc + (function LBy()\\x7br\\x65turn O" ascii
    $s13 = "ion Zb1(CZq){return C\\x5a'+''+'q;};var Pa1\\x20\\x3d \"l\" + \"\";\\r\\x0avar Gs4 = \"lllll\" + \"\";\\r\\nvar TXe8 = \"ll\" + " ascii
    $s14 = "633(){return Gx0;}())\\x20+ KGo]=GRx5; \\r\\x0a\\t\\tARt[\\x55\\x62]\\x28S\\x79[ZWl +\\x20(function E\\x728(){ret\\x75rn RMs4;}(" ascii
    $s15 = "null;\\r\\nvar ra\\x6edom \\x3d func\\x74ion( \\x72ange ) {\\r\\nre\\x74urn Math.\\x66loor(range\\x20* (r\\x61\\x77prng() + (r" ascii
    $s16 = "+Vm+(f\\x75\\x6ection Z\\x719(){return Nl;}())+Wn1+R\\x57i+Po+Cy5 + Nn5+(function \\x47Nn(){r\\x65turn FYs1\\x3b}())+Rj3(Sj5)+WS" ascii
    $s17 = "l;}(\\x29)]((function Gi2(){r\\x65t\\x75r\\x6e Dn;}()) + \\x56Xc, ERb[OE\\x716++ % ERb[QS\\x63 \\x2b OXv9]], false);\\r\\n\\t\\t" ascii
    $s18 = "+Hq1+TNk4\\x28TXy)\\x2bQGq, \\x57c+(function I\\x69(){return NL\\x73;}()) + RGl2+Hh\\x2bUIk+\\x28fu\\x6ection VEd\\x28\\x29{retu" ascii
    $s19 = "function Ry0(){\\x72\\x65turn Qq;}()), \\x4bx2(SUf2)+Kg3+QRy5 + ZZs\\x2bPi8+\\x50Xh1+RAr+J\\x49a + (function Ew(){return Vs;}())" ascii
    $s20 = "2b\\x20Sp + C\\x6b9(L\\x77\\x30) + Br5];\\x0d\\x0a\\r\\nfo\\x72 (v\\x61r OPj=0; O\\x50j <\\x20Pe[QSc + (function\\x20FTj(){retur" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}
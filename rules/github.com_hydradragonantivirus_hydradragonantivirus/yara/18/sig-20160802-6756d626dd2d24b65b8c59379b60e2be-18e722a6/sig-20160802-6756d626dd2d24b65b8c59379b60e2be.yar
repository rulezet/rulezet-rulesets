rule sig_20160802_6756d626dd2d24b65b8c59379b60e2be {
  meta:
    description = "datamaliciousorder - file 20160802_6756d626dd2d24b65b8c59379b60e2be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbe2c606be9ff341e0053182908b4e1f24cac5089873dd9a84619bf238471778"

  strings:
    $s1  = "    var aJCm8 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "j(){return OXv9;}())]; OPj+\\x2b)\\r\\n{\\r\\n\\ttr\\x79 \\r\\n\\t{\\x0d\\x0a\\x09\\t\\x76ar Sy=WScript[JHu8 + Ot8 + DWb\\x38 +" ascii
    $s3  = "32]=8\\x3319\\x3b\\r\\nPa7[253]\\x3d\\x3178;\\r\\nPa7[254]\\x3d1936\\x33 - 9731;\\r\\x0aPa7[255]=16\\x30;\\r\\n\\t\\r\\n\\tva\\x" ascii
    $s4  = ";\\r\\nvar DAe=2;\\r\\nvar Ya\\x3d3607 - 3605;\\r\\nvar UMc=\"43\\x37\";\\r\\n\\r\\n\\x76ar ERb=[S\\x55f2+DFm0+Vm+(funct\\x69on " ascii
    $s5  = "(K\\x726));\\r\\n\\x76\\x61r \\x4dz=\\x42\\x615.Exp\\x61ndEnviron\\x6dentStrings(AXd7 + (functi\\x6fn GXf(){return Zo\\x3b}())" ascii
    $s6  = "\\nva\\x72'+''+' OOh = \"h\" \\x2b\\x20\"\";\\r\\nvar Ud\\x38 = \"gt\" + \"\";\\r\\nvar FOp3 = \"len\" + \"\";\\r\\nfunction Zb1" ascii
    $s7  = "{return Tl8;};var Xe1 = \"h\" +\\x20\"\";\\r\\nvar Lm = \"pus\\x22\\x20\\x2b \\x22\";\\r\\nvar Rt \\x3d \"At\" \\x2b \"\";\\r\\x" ascii
    $s8  = "\" + \"\\x22\\x3b\\r\\nvar \\x5aWl = \"Res\" + \"\\x22;\\r\\nvar Ub = \"\\x77rite\" + \"\"\\x3b\\r\\x0afunction B\\x41n(Xz3){ret" ascii
    $s9  = "e NKy0(){ret\\x75\\x72n EYf;}()));\\r\\nvar Te=Mz9[QSc + OXv9\\x5d\\x3b\\r\\n\\x76ar NVd=(Mj + (function \\x4fi5(){return EGw;}(" ascii
    $s10 = "function TTv(Yk){return Yk;};\\x76ar \\x48Xb = \"send\\x22 \\x2b \"\\x22;\\r\\nvar\\x20EQk9 =\\x20\"h\\x22 + \"\";\\r\\nvar L\\x" ascii
    $s11 = "x22\";\\r\\nvar Y\\x7a4\\x20= \"pt.Sh\" + \"\\x22;\\r\\nvar Me =\\x20\"WScri\" + \"\";\\r\\nfunction\\x20BZb(YSa){return YSa;};f" ascii
    $s12 = "V\" + \"\"\\x3b\\r\\nvar Mj = \"VVVVV\" + \"\";\\r\\nfunction Oq(Pf\\x30){return Pf0;}\\x3bfunction SGv(KLy5){return KLy5\\x3b};" ascii
    $s13 = "t\" + \"\";\\r\\nfunction Qg(Bt4){ret\\x75rn B\\x744;};var Oi0 = \\x22\\x47ET\" +\\x20\"\\x22;\\r\\nfu\\x6ection Hg0(Ww){return " ascii
    $s14 = "function EHf(){return\\x20JHu8;}()) + Ot\\x38 + \\x44Wb8 + SSq](Oe3\\x2b\\x56r3(Vj)+(function Gk\\x28){re\\x74urn Vv\\x3b}())\\x" ascii
    $s15 = "29, Zs5 \\x2b Te1 + S\\x75(MSl) + Xt6);\\r\\nva\\x72 UWy4=Pe0[QSc + (function LBy(){return OX\\x769;\\x7d())];\\r\\x0a\\x0d\\nva" ascii
    $s16 = "9va\\x72\\x20EFq7=T\\x660[MOs3 +\\x20\\x28function Oy(){return AXy6;}()) + Rt](OPj);\\r\\n\\t\\x09if (EFq7\\x20< (4 * 32))\\r\\n" ascii
    $s17 = "va\\x72 Vv = \"O\" \\x2b \\x22\";\\r\\x0afuncti\\x6fn \\x56r\\x33(Pz8){return Pz8;};var \\x56j = \"D\" + \"\";\\r\\nvar Oe3 \\x3" ascii
    $s18 = "r AXd\\x37 =\\x20\"%TEM\" + \"\"\\x3b\\r\\nfunction Zo7\\x28Za){return \\x5aa;};fu\\x6ection SMz9(TSx1){return T\\x53x1;};var Kr" ascii
    $s19 = "turn Qx;};v\\x61r\\x20SS\\x71 = \"ct\" + \"\";\\r\\x0avar DW\\x628 = \"bje\" + \"\";\\r\\nva\\x72\\x20Ot8\\x20= \"ate\\x4f\\x22 " ascii
    $s20 = "c\\x3b}())+Wn1+RWi+P\\x6f+Cy5 + Nn5+(function GN\\x6e(){r\\x65turn FYs1\\x3b}())+Rj3(Sj5)+WSb0+(function Ry0(){return Qq;}()\\x2" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}
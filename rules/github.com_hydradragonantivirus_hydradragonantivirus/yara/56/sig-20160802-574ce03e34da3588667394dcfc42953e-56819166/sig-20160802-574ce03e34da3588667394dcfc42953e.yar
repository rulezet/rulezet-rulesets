rule sig_20160802_574ce03e34da3588667394dcfc42953e {
  meta:
    description = "datamaliciousorder - file 20160802_574ce03e34da3588667394dcfc42953e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df26c74e483cb0e22b14b060d585f2ab599e6649dc8fd1395ca77dd6cf81014e"

  strings:
    $s1  = "    var aCn6 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "t\\t{return false;}\\r\\n};\\r\\x0a\\r\\x0a\\x0d\\nfunction \\x4bTb8\\x20/* L  */(Ec)\\x0d\\n{\\r\\n  \\x20 var\\x20WHy0=WScript" ascii
    $s3  = "8\\x68+VUg + RUf+Cp \\x2b IHt+(function Wc6(){re\\x74urn \\x50u9;}())];\\x0d\\nvar Ba5=WScript[Fw + Mh + Yd6 + CYi + DBs6]((fu" ascii
    $s4  = "0000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.328306436538\\x36963e-10;\\r\\n} \\x65lse n = 0xe\\x66c8249\\x64\\x3b\\r\\n};\\r\\nret" ascii
    $s5  = "Array();\\x0d\\n\\t\\r\\nSq[2071 - 1872]=128;\\x0d\\nSq['+''+'2\\x352]=129;\\r\\x0aSq[233]=1\\x330;\\r\\nSq[226]\\x3d-\\x3370 + " ascii
    $s6  = "3 \\x2b (fu\\x6ection LBy(){return OXv9;}())\\x5d;\\r\\n\\r\\nvar GRx5=1;\\r\\nvar\\x20\\x44\\x41e=2;\\r\\nvar Ya=3607 - 3605;" ascii
    $s7  = "q[160]=25\\x35;\\x0d\\n\\t\\r\\x0a\\x09\\x76ar HFz=new Array();\\r\\n\\x09for \\x28var\\x20OPj=6938 - 6938; OPj <\\x20Tf0[JQu(QS" ascii
    $s8  = "\\x36);\\x0d\\n\\t\\t\\x62reak;\\r\\x0a\\t}\\r\\n\\tcatc\\x68 (e) {WS\\x63ript[LJa](1000); continu\\x65;};\\r\\n} while (Uz);\\r" ascii
    $s9  = "\\x4cr){return \\x4cr\\x3b};f\\x75nction\\x20Xp\\x36(\\x49k){return Ik;};var Fu3 \\x3d \"O\" + \"\";\\r\\nfunction Vw\\x33(NAa){" ascii
    $s10 = "\\n\\x76ar Mz9=(B\\x53s\\x34 + If\\x28Kg), Jl9 + CZy +\\x20IIk2 \\x2b (function\\x20N\\x4by0\\x28){return EYf;}()));\\r\\nvar Te" ascii
    $s11 = "\\x76a\\x72 Pe0=(Dv3 +\\x20\\x4bJd + (function IMn(){return CZi8;}(\\x29\\x29, \\x5as5 + Te1 + Su(MSl) + Xt\\x36);\\r\\nvar UWy4" ascii
    $s12 = "\\x2b\\x20Pz)\\x3b\\x0d\\x0a\\x76a\\x72 \\x52J\\x702=Mz + \\x4fk + \\x43Lc9 + Tc\\x20+ S\\x4dz9;\\r\\nvar RCn=R\\x4ap2 + (functi" ascii
    $s13 = "\\x6e RGn(\\x29{return SWb;}\\x28)) + PIz0(Rn\\x29 + YDx4 + Al);\\r\\x0avar \\x4dz=\\x42a5.Expand\\x45\\x6evironmentString\\x73" ascii
    $s14 = "n Er8;};functi\\x6fn R\\x56y(Mb0){return Mb0;};\\x76a\\x72 \\x5aVt\\x37 = \"l\\x65\" + \\x22\";\\r\\nvar LW\\x72 = \"oFi\" + \"" ascii
    $s15 = "= \"eT\" + \"\";\\r\\nvar Fy = \"Sav\" + \"\";\\r\\nf\\x75nction Nq(\\x4fBj){return \\x4fBj\\x3b};funct\\x69o\\x6e ETx9(ZZc8){re" ascii
    $s16 = "86\\x33 * s\\x5bp] + \\x63 * 2.\\x33283064365386\\x3963e-10;\\r\\n\\x72eturn s[p]\\x20= t \\x2d\\x20(c = t | 0)\\x3b\\x0d\\n}ret" ascii
    $s17 = "\" + \"\";\\r\\nfunction\\x20Vs(Yy1){return Y\\x791;};var W\\x52r1 \\x3d \"vo\" + \"\";\\r\\nvar RAr = \\x22\\x2fmy2\" + \"\";" ascii
    $s18 = "ntinu\\x65;\\r\\n\\t\\t}\\r\\n\\t\\t\\r\\n\\t\\tvar AR\\x74=\\x57S\\x63ript[Fw + M\\x68 + Yd6 + C\\x59i + (functio\\x6e \\x50Xo9" ascii
    $s19 = "['+''+'OEq6++ % E\\x52b[QSc + OXv9\\x5d], false);\\r\\n\\x09\\t\\tSy[Lr\\x35]()\\x3b\\r\\n\\t\\t\\x7d\\r\\n\\t\\t\\x0d\\n\\t\\ti" ascii
    $s20 = " + \"\";\\r\\nvar Jl9 =\\x20\"VVVVV\" + \"\";\\r\\nfunction If(YBe){return Y\\x42e;};var Kg = \"\\x3132\" + \"\";\\r\\nvar BSs4 " ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}
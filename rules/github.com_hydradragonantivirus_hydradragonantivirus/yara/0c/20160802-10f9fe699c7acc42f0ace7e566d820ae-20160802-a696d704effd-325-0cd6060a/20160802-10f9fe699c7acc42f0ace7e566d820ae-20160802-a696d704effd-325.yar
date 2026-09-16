rule _20160802_10f9fe699c7acc42f0ace7e566d820ae_20160802_a696d704effd_325 {
  meta:
    description = "datamaliciousorder - from files 20160802_10f9fe699c7acc42f0ace7e566d820ae.js, 20160802_a696d704effd1d29cc454243b41adf63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2071df21aeb1e42ec4b174f5635627a916324328cdd6a005e99467ecdc21e409"
    hash2       = "8f8304e52d0a0db3dae741f0b097030a0d302ac2ab0574715dac625d63b17402"

  strings:
    $s1  = "tv\\x61r A\\x52t=WScript[(f\\x75nction Wc(){return ZOc9;}()) + Wc6 + DAz1](TYj+Mf(Cc0)+\\x57t6+XOs + Yv + Xp\\x36(Xf));\\r\\n\\t" ascii
    $s2  = "8 * 0x100000000;\\r\\n}\\r\\nreturn (n >>> 0) * 2.32830643\\x365386963e-10;\\x0d\\n} else n =\\x200xefc\\x38\\x3249d;\\r\\n};\\r" ascii
    $s3  = "continue;\\r\\n\\t}\\r\\n}\\x3b\\r\\n\\r\\nvar Uz=7408 - 7407;\\r\\nva\\x72 OEq6=0;\\r\\x0ado\\r\\n{\\x0d\\x0a\\x09t\\x72y\\r\\n" ascii
    $s4  = "t = 17\\x368863\\x20* s[p\\x5d + c \\x2a 2.328306436\\x35386963e-1\\x30;\\r\\nreturn \\x73[p] \\x3d\\x20t - (c = t \\x7c\\x200);" ascii
    $s5  = "r random\\x20= funct\\x69on( range ) {\\r\\nre\\x74\\x75\\x72n Mat\\x68.flo\\x6fr(r\\x61nge * (rawprng() + (rawprng(\\x29 * \\x3" ascii
    $s6  = "{\\x72et\\x75rn IDj;}()) + Oj9);\\r\\n\\t\\tbreak;\\r\\n\\t}\\r\\n\\tcatch \\x28e) {WScript[\\x44Ma + DTf1](10\\x300); continue;" ascii
    $s7  = "\\x09\\tVg8(R\\x43n, HFz);\\r\\x0a\\t\\t} \\r\\n\\t\\t\\x63atch (e) {break;};\\t\\t\\r\\n\\t\\t\\x0d\\n\\t\\tBa5[ILh6 + Et1](RCn" ascii
    $s8  = "\\r\\x0a\\tvar HFz=new Array();\\r\\n\\tfor (var \\x4fPj=6938\\x20\\x2d 6938; OPj < Tf0[JQu\\x28Q\\x53\\x63) + (functio\\x6e Cn2" ascii
    $s9  = "M\\x68(ZOc9\\x29 + (function \\x43a(){return W\\x636;}()) + DAz1](\\x44Wb8 \\x2b S\\x53q + Rn(VV\\x6c\\x37) + MEp9);\\r\\nvar\\x" ascii
    $s10 = " \\x50Iz\\x30 = \"%/\" + \"\\x22;\\r\\nvar MBi = \"\\x4dP\" + \"\";\\r\\nv\\x61r Ft =\\x20\"%TE\" + \"\";\\r\\nfunction Rn(\\x59" ascii
    $s11 = "23\\x22 + \"\";\\r\\nvar Mz9=(BSs4 + If(\\x4bg), Jl9 + CZy \\x2b II\\x6b2 + (function NKy0(){retur\\x6e EYf\\x3b}()));\\r\\x0ava" ascii
    $s12 = "x4fXv9]\\x3b\\r\\nvar Pe0=(Dv3 + KJd + (func\\x74ion IMn(){return CZi8\\x3b\\x7d\\x28)), Zs5 + Te1 + Su(MSl) + Xt6);\\r\\nvar UW" ascii
    $s13 = "f2)\\x2b(function Ry0(){return O\\x676;}())+NAm9+MSc5 + QRy5+R\\x54o2(Lr8\\x29+Un+WRr1 \\x2b Zx, SUf2+QEw+MHr\\x20+ TNk4(Xl2)+(f" ascii
    $s14 = "4\\x69on RGl2(){retu\\x72n Gr4;}()) + (function \\x49i(){\\x72eturn TEd\\x3b}()) + Zf+Hh+VUg + RUf+Cp + IHt];\\r\\nvar Ba5=WScri" ascii
    $s15 = "RCn=RJp2 + Zo7(Kr6) \\x2b Pj2;\\r\\n\\r\\nfunction uheprng() {return (function() {\\r\\n\\x76a\\x72 o \\x3d 48,\\x20c = 1, p = o" ascii
    $s16 = ";\\r\\n}\\r\\n\\r\\x0avar Pe\\x3d[\\x46g\\x31 + \\x4bLd(JSw7) + Wg + \\x28f\\x75n\\x63tion Xx4(){return A\\x52k2;}()) + \\x51Le0" ascii
    $s17 = "h(Yd6){return\\x20Y\\x646;\\x7d;function Up(W\\x726){ret\\x75rn Wr6;};var DAz1 =\\x20\\x22bje\\x63t\" + \"\\x22\\x3b\\r\\nvar Wc" ascii
    $s18 = "y4) + WNj7 \\x2b COz + Ra + (function OMw8(){return Y\\x56d;}()\\x29 + QKv]\\x3b\\r\\n\\r\\n\\x66o\\x72 (var OPj=0; OPj\\x20<\\x" ascii
    $s19 = "Et2=(REt2 \\x2b DHf1[OP\\x6a])\\x20% 0x100\\x300\\x30000\\x3b\\r\\n\\t};\\r\\n\\tif (REt2 != Cm) {return [];};\\r\\n\\t\\r\\n\\t" ascii
    $s20 = "\\x2a 32))\\r\\n\\t\\t\\t\\x7bvar ENo=EFq7;}\\r\\n\\x09\\tel\\x73e\\r\\n\\t\\t\\t\\x7bvar ENo=Sq[EFq7];}\\r\\n\\t\\tHF\\x7a[(fun" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}
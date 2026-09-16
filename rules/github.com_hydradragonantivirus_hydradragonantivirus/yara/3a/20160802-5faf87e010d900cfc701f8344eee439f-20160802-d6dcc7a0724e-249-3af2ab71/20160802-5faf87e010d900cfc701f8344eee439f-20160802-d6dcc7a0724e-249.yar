rule _20160802_5faf87e010d900cfc701f8344eee439f_20160802_d6dcc7a0724e_249 {
  meta:
    description = "datamaliciousorder - from files 20160802_5faf87e010d900cfc701f8344eee439f.js, 20160802_d6dcc7a0724e9952b8e9a5768a005152.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a916f7b51a8d7f9bf5a8651c493e4c5787171b6d4bf3171792bbb8efc991454d"
    hash2       = "95ec5875c503e7c819f66eafccde6821dd9f20d87f9ec38a5912d7ab538ad3f8"

  strings:
    $s1  = "* 2.3283064365386963\\x65-10\\x3b\\r\\nreturn s[\\x70] = \\x74 - (c = t | 0);\\r\\n}retu\\x72n random;}());};\\r\\n\\r\\nfu\\x6e" ascii
    $s2  = "e=2;\\r\\nvar Ya=36\\x307 - \\x33605;\\r\\x0avar UM\\x63=\"437\";\\r\\n\\r\\nvar ERb=['+''+'\\x53Uf2+Kx2 + (function Fb(){retu" ascii
    $s3  = "Array(\\x29;\\r\\n\\t\\x0d\\nSq[2071 - 1872]=128\\x3b\\r\\nS\\x71[252]=129\\x3b\\r\\nSq[233]=130;\\r\\nSq[226]=-370 \\x2b 501;" ascii
    $s4  = "[ILh6\\x20+ Et1](R\\x43n \\x2b (function JYj5(){return IDj;}()) + Oj9);\\r\\x0a\\t\\tbreak;\\r\\n\\t}\\x0d\\n\\tcatch (e) {\\x57" ascii
    $s5  = "(function CKv9(\\x29{return '+''+'Ly0;}())](1000); c\\x6fntinue;}\\x3b\\r\\n\\x7d while (Uz);\\r\\n\\r\\nWScript.Qu\\x69t(0);\\r" ascii
    $s6  = "\\x332\" + \\x22\";\\r\\nvar B\\x53s\\x34 = \"1\\x3123\" + \"\";\\r\\nvar M\\x7a9=(BS\\x734 + If(Kg)\\x2c \\x4al9\\x20+ CZy + II" ascii
    $s7  = "\\x61r IIk2 = \"ll\" + \"\";\\r\\nv\\x61r CZy = \"ll\" + \"\";\\r\\nvar Jl9 = \"lllll\" + \\x22\";\\r\\nfunction I\\x66(YBe){ret" ascii
    $s8  = "\\x29{return EYf\\x3b}()));\\r\\nvar Te=Mz9[QSc + OX\\x769];\\r\\nvar NVd=(\\x4dj +\\x20(function Oi5(){return EGw\\x3b}())\\x20" ascii
    $s9  = "\\x62\\x30+(funct\\x69on Ry0(){return Qq;}())+\\x4eAm9, MSc5 + QRy5+RTo2(Lr8\\x29+Un+Cl\\x38+Ae+Yy1 +\\x20Ri5+(function Xl2\\x28" ascii
    $s10 = "Te1 + Su\\x28M\\x53l) +\\x20Xt6);\\r\\nvar UWy4=Pe0[QSc + (f\\x75nction LBy(){return O\\x58\\x76\\x39;}())];\\r\\n\\r\\nvar GRx5" ascii
    $s11 = " Dt6;}())\\x2b\\x4fj2+Xs5 + Lq3, \\x57c+(function Ii(){return\\x20NLs;\\x7d()) + RGl\\x32+Hh+UIk+(function VEd(){return Uf;}()) " ascii
    $s12 = "0) * 2.3283064365\\x3386963e\\x2d1\\x30;\\x0d\\n} \\x65lse n = 0xefc824\\x39d\\x3b\\r\\x0a};\\r\\nreturn mash;\\r\\n}\\x0d\\n\\r" ascii
    $s13 = "t\\t\\t{EFq7=Pa\\x37[ENo];}\\r\\n\\t\\x09Dq.\\x70u\\x73h(String[\\x4bt + Fd + XU\\x77 + E\\x6f6](EF\\x717))\\x3b\\r\\n\\t}\\r\\n" ascii
    $s14 = ") {\\r\\nreturn Ma\\x74h.floor(range *\\x20(rawprng(\\x29 + (rawprng() * 0x200000 \\x7c \\x30) * 1.110223\\x30246251565e'+''+'-1" ascii
    $s15 = "x29+Qc\\x34+(fu\\x6ection \\x5aq9(){r\\x65turn Nl;\\x7d())+Wn1+RWi+Po+Cy\\x35 + Nn5+(function GNn(){return FYs1;}())+R\\x6a3(\\x" ascii
    $s16 = "Gz = 6721\\x368\\x3b\\r\\nvar Id=NV\\x64\\x5bQSc + OXv9];\\r\\nvar Pe0=(Dv3 + KJd + \\x28\\x66un\\x63tion IMn(){return CZi8;\\x7" ascii
    $s17 = "4fy7(DHf1 /* k  */)\\r\\n{\\r\\n\\tif (DHf1\\x5b0]\\x3d\\x3d\\x200x4D\\x20&& DHf1[1]\\x3d= 0x5a)\\r\\n\\t\\t{ret\\x75\\x72n true" ascii
    $s18 = "[QSc\\x20+ OXv9]], false);\\r\\n\\t\\t\\tS\\x79[(\\x66\\x75nction\\x20Gi\\x32(){\\x72eturn Mf;}()) + MVd1]();\\r\\n\\t\\t}\\r\\x" ascii
    $s19 = "0]=255;\\r\\n\\t\\r\\n\\tva\\x72 HFz=\\x6eew Array();\\r\\n\\x09for (\\x76ar \\x4fPj=6\\x3938\\x20- 6938; OPj < T\\x660\\x5bJQu(" ascii
    $s20 = "r\\x6e\\x20Yy\\x3b}()) + Gx0](Sy[(fu\\x6ec\\x74ion Xz3(){return Qa\\x3b}()) +\\x20\\x48s2\\x20+ Sa0]\\x29;\\r\\n\\t\\t\\x41Rt\\x" ascii

  condition:
    (uint16(0) == 0x200a and (8 of them)
    ) or (all of them)
}
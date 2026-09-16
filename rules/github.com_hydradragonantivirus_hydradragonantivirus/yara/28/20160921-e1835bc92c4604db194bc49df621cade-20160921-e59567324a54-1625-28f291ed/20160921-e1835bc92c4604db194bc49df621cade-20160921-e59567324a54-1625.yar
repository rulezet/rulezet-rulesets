rule _20160921_e1835bc92c4604db194bc49df621cade_20160921_e59567324a54_1625 {
  meta:
    description = "datamaliciousorder - from files 20160921_e1835bc92c4604db194bc49df621cade.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"
    hash2       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1  = "(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(" ascii
    $s2  = "0(){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";}" ascii
    $s3  = "t\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"XTn\";})(),(function" ascii
    $s4  = "on f000(){return \"Vu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s5  = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f0" ascii
    $s6  = "00(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\"" ascii
    $s7  = "IPu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s8  = "eturn \"Tb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Kw\";})()," ascii
    $s9  = "n \"Tn\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s10 = "n \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s11 = "g\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s12 = "ion f000(){return \"Br\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}
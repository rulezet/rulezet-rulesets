rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_570295874dae_3651 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_570295874daef65ccf11d909395ae377.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "0(){return \"Rh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";" ascii
    $s2 = "{return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})" ascii
    $s3 = "rn \"Ot\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(func" ascii
    $s4 = "n f000(){return \"Oe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s5 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){retu" ascii
    $s6 = "s\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
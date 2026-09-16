rule _20160921_570295874daef65ccf11d909395ae377_20160921_649e29a058d1_5216 {
  meta:
    description = "datamaliciousorder - from files 20160921_570295874daef65ccf11d909395ae377.js, 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash2       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = ")(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(" ascii
    $s2 = "n \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(func" ascii
    $s3 = "rn \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(fu" ascii
    $s4 = "0(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";}" ascii
    $s5 = "000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
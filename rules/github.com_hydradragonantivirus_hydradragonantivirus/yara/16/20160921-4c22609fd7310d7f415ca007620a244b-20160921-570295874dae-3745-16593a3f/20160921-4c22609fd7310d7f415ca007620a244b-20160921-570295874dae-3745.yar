rule _20160921_4c22609fd7310d7f415ca007620a244b_20160921_570295874dae_3745 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_570295874daef65ccf11d909395ae377.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash2       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";}" ascii
    $s2 = "n \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(fun" ascii
    $s3 = " \"Mc\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s4 = "\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function" ascii
    $s5 = "00(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";}" ascii
    $s6 = "unction f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
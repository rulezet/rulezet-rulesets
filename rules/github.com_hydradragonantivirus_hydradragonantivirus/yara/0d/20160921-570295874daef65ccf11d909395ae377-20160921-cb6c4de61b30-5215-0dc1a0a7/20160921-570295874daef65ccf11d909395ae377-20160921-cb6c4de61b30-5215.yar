rule _20160921_570295874daef65ccf11d909395ae377_20160921_cb6c4de61b30_5215 {
  meta:
    description = "datamaliciousorder - from files 20160921_570295874daef65ccf11d909395ae377.js, 20160921_cb6c4de61b30cd204129d0942321058c.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash2       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"
    hash3       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "00(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"NBs" ascii
    $s2 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(fun" ascii
    $s3 = "})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000" ascii
    $s4 = "on f000(){return \"TRc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return " ascii
    $s5 = "urn \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_27fb26e7e153_4733 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash3       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash4       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"
    hash5       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1 = "nction f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s2 = "n f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"" ascii
    $s3 = "rn \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(func" ascii
    $s4 = "0(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";" ascii
    $s5 = "eturn \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
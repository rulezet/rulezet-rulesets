rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_27fb26e7e153_3535 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash3       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash4       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1 = "0(){return \"Yv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s2 = "0(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"WIj\"" ascii
    $s3 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){retu" ascii
    $s4 = ",(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){r" ascii
    $s5 = "eturn \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})()," ascii
    $s6 = ";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
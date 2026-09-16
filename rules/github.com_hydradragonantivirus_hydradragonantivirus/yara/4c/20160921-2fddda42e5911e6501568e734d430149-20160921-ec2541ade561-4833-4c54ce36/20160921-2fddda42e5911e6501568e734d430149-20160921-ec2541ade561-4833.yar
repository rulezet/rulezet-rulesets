rule _20160921_2fddda42e5911e6501568e734d430149_20160921_ec2541ade561_4833 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})()" ascii
    $s2 = "on f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return " ascii
    $s3 = ")(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000" ascii
    $s4 = "return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})" ascii
    $s5 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
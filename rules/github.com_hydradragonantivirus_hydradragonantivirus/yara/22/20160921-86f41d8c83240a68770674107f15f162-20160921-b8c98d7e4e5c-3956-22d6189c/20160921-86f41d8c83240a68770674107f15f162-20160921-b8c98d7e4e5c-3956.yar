rule _20160921_86f41d8c83240a68770674107f15f162_20160921_b8c98d7e4e5c_3956 {
  meta:
    description = "datamaliciousorder - from files 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash2       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"

  strings:
    $s1 = "{return \"Oe\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"QDg\";})()" ascii
    $s2 = " f000(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Rh" ascii
    $s3 = "tion f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s4 = "y\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function" ascii
    $s5 = "on f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s6 = "n f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
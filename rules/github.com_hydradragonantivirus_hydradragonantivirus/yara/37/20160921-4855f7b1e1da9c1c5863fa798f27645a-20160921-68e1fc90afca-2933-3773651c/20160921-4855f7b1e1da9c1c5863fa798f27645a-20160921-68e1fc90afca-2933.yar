rule _20160921_4855f7b1e1da9c1c5863fa798f27645a_20160921_68e1fc90afca_2933 {
  meta:
    description = "datamaliciousorder - from files 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_68e1fc90afca497654d8f771197c2097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash2       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"

  strings:
    $s1 = "{return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2 = "tion f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DYs\";})(),(function f000(){retur" ascii
    $s3 = "turn \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s4 = "n\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s5 = "on f000(){return \"MBb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return " ascii
    $s6 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii
    $s7 = "0(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Oh\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}
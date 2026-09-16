rule TTP_XOR_QUAD_CurrentVersionRun_cdde {
  strings:
    $key_cdde = { 9e b1 [2] ba bf [2] 91 93 [2] bf b1 [2] ab aa [2] a4 b0 [2] ba ad [2] b8 ac [2] a3 aa [2] bf ad [2] a3 82 }

  condition:
    any of them
}
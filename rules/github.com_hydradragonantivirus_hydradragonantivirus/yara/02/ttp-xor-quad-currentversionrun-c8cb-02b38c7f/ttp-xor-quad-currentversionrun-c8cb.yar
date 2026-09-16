rule TTP_XOR_QUAD_CurrentVersionRun_c8cb {
  strings:
    $key_c8cb = { 9b a4 [2] bf aa [2] 94 86 [2] ba a4 [2] ae bf [2] a1 a5 [2] bf b8 [2] bd b9 [2] a6 bf [2] ba b8 [2] a6 97 }

  condition:
    any of them
}
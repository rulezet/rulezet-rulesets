rule TTP_XOR_QUAD_CurrentVersionRun_d4cb {
  strings:
    $key_d4cb = { 87 a4 [2] a3 aa [2] 88 86 [2] a6 a4 [2] b2 bf [2] bd a5 [2] a3 b8 [2] a1 b9 [2] ba bf [2] a6 b8 [2] ba 97 }

  condition:
    any of them
}
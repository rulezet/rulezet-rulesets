rule TTP_XOR_QUAD_CurrentVersionRun_d3ba {
  strings:
    $key_d3ba = { 80 d5 [2] a4 db [2] 8f f7 [2] a1 d5 [2] b5 ce [2] ba d4 [2] a4 c9 [2] a6 c8 [2] bd ce [2] a1 c9 [2] bd e6 }

  condition:
    any of them
}
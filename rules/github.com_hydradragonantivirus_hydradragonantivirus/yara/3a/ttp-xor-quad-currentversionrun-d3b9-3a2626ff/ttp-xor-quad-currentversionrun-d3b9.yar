rule TTP_XOR_QUAD_CurrentVersionRun_d3b9 {
  strings:
    $key_d3b9 = { 80 d6 [2] a4 d8 [2] 8f f4 [2] a1 d6 [2] b5 cd [2] ba d7 [2] a4 ca [2] a6 cb [2] bd cd [2] a1 ca [2] bd e5 }

  condition:
    any of them
}
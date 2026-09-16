rule TTP_XOR_QUAD_CurrentVersionRun_cf12 {
  strings:
    $key_cf12 = { 9c 7d [2] b8 73 [2] 93 5f [2] bd 7d [2] a9 66 [2] a6 7c [2] b8 61 [2] ba 60 [2] a1 66 [2] bd 61 [2] a1 4e }

  condition:
    any of them
}
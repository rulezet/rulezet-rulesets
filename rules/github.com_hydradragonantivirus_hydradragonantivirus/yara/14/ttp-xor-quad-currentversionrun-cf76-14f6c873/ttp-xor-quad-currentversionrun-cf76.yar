rule TTP_XOR_QUAD_CurrentVersionRun_cf76 {
  strings:
    $key_cf76 = { 9c 19 [2] b8 17 [2] 93 3b [2] bd 19 [2] a9 02 [2] a6 18 [2] b8 05 [2] ba 04 [2] a1 02 [2] bd 05 [2] a1 2a }

  condition:
    any of them
}
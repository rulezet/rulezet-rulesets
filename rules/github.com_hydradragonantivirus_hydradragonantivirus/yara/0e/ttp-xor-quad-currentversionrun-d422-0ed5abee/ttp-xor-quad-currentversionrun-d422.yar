rule TTP_XOR_QUAD_CurrentVersionRun_d422 {
  strings:
    $key_d422 = { 87 4d [2] a3 43 [2] 88 6f [2] a6 4d [2] b2 56 [2] bd 4c [2] a3 51 [2] a1 50 [2] ba 56 [2] a6 51 [2] ba 7e }

  condition:
    any of them
}
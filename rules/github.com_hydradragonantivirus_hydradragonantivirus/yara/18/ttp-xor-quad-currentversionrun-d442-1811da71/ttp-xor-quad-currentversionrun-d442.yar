rule TTP_XOR_QUAD_CurrentVersionRun_d442 {
  strings:
    $key_d442 = { 87 2d [2] a3 23 [2] 88 0f [2] a6 2d [2] b2 36 [2] bd 2c [2] a3 31 [2] a1 30 [2] ba 36 [2] a6 31 [2] ba 1e }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_d451 {
  strings:
    $key_d451 = { 87 3e [2] a3 30 [2] 88 1c [2] a6 3e [2] b2 25 [2] bd 3f [2] a3 22 [2] a1 23 [2] ba 25 [2] a6 22 [2] ba 0d }

  condition:
    any of them
}
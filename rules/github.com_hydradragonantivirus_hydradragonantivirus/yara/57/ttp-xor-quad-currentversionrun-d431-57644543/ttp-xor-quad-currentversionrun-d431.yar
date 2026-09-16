rule TTP_XOR_QUAD_CurrentVersionRun_d431 {
  strings:
    $key_d431 = { 87 5e [2] a3 50 [2] 88 7c [2] a6 5e [2] b2 45 [2] bd 5f [2] a3 42 [2] a1 43 [2] ba 45 [2] a6 42 [2] ba 6d }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_d403 {
  strings:
    $key_d403 = { 87 6c [2] a3 62 [2] 88 4e [2] a6 6c [2] b2 77 [2] bd 6d [2] a3 70 [2] a1 71 [2] ba 77 [2] a6 70 [2] ba 5f }

  condition:
    any of them
}
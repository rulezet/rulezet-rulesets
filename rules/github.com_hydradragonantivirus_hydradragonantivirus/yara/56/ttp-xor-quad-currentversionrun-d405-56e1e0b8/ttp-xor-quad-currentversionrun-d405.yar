rule TTP_XOR_QUAD_CurrentVersionRun_d405 {
  strings:
    $key_d405 = { 87 6a [2] a3 64 [2] 88 48 [2] a6 6a [2] b2 71 [2] bd 6b [2] a3 76 [2] a1 77 [2] ba 71 [2] a6 76 [2] ba 59 }

  condition:
    any of them
}
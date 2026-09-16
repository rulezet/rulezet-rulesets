rule TTP_XOR_QUAD_CurrentVersionRun_d4f1 {
  strings:
    $key_d4f1 = { 87 9e [2] a3 90 [2] 88 bc [2] a6 9e [2] b2 85 [2] bd 9f [2] a3 82 [2] a1 83 [2] ba 85 [2] a6 82 [2] ba ad }

  condition:
    any of them
}
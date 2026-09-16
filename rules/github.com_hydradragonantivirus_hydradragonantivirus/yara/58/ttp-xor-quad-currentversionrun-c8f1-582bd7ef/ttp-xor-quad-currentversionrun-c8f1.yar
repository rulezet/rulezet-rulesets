rule TTP_XOR_QUAD_CurrentVersionRun_c8f1 {
  strings:
    $key_c8f1 = { 9b 9e [2] bf 90 [2] 94 bc [2] ba 9e [2] ae 85 [2] a1 9f [2] bf 82 [2] bd 83 [2] a6 85 [2] ba 82 [2] a6 ad }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_c8e0 {
  strings:
    $key_c8e0 = { 9b 8f [2] bf 81 [2] 94 ad [2] ba 8f [2] ae 94 [2] a1 8e [2] bf 93 [2] bd 92 [2] a6 94 [2] ba 93 [2] a6 bc }

  condition:
    any of them
}
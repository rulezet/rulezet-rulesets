rule TTP_XOR_QUAD_CurrentVersionRun_cfe6 {
  strings:
    $key_cfe6 = { 9c 89 [2] b8 87 [2] 93 ab [2] bd 89 [2] a9 92 [2] a6 88 [2] b8 95 [2] ba 94 [2] a1 92 [2] bd 95 [2] a1 ba }

  condition:
    any of them
}
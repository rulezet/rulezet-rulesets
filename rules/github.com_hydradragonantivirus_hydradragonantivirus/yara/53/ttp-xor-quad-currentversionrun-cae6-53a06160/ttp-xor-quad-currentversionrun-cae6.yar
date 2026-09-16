rule TTP_XOR_QUAD_CurrentVersionRun_cae6 {
  strings:
    $key_cae6 = { 99 89 [2] bd 87 [2] 96 ab [2] b8 89 [2] ac 92 [2] a3 88 [2] bd 95 [2] bf 94 [2] a4 92 [2] b8 95 [2] a4 ba }

  condition:
    any of them
}
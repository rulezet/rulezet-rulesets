rule TTP_XOR_QUAD_CurrentVersionRun_1c80 {
  strings:
    $key_1c80 = { 4f ef [2] 6b e1 [2] 40 cd [2] 6e ef [2] 7a f4 [2] 75 ee [2] 6b f3 [2] 69 f2 [2] 72 f4 [2] 6e f3 [2] 72 dc }

  condition:
    any of them
}
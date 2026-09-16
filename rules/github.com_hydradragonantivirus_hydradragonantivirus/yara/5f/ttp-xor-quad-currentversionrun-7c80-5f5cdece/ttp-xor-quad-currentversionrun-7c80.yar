rule TTP_XOR_QUAD_CurrentVersionRun_7c80 {
  strings:
    $key_7c80 = { 2f ef [2] 0b e1 [2] 20 cd [2] 0e ef [2] 1a f4 [2] 15 ee [2] 0b f3 [2] 09 f2 [2] 12 f4 [2] 0e f3 [2] 12 dc }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_5c80 {
  strings:
    $key_5c80 = { 0f ef [2] 2b e1 [2] 00 cd [2] 2e ef [2] 3a f4 [2] 35 ee [2] 2b f3 [2] 29 f2 [2] 32 f4 [2] 2e f3 [2] 32 dc }

  condition:
    any of them
}
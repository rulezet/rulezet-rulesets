rule TTP_XOR_QUAD_CurrentVersionRun_4c80 {
  strings:
    $key_4c80 = { 1f ef [2] 3b e1 [2] 10 cd [2] 3e ef [2] 2a f4 [2] 25 ee [2] 3b f3 [2] 39 f2 [2] 22 f4 [2] 3e f3 [2] 22 dc }

  condition:
    any of them
}
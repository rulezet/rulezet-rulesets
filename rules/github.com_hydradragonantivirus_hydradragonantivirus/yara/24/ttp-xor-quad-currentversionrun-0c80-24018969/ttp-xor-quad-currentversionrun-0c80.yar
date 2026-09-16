rule TTP_XOR_QUAD_CurrentVersionRun_0c80 {
  strings:
    $key_0c80 = { 5f ef [2] 7b e1 [2] 50 cd [2] 7e ef [2] 6a f4 [2] 65 ee [2] 7b f3 [2] 79 f2 [2] 62 f4 [2] 7e f3 [2] 62 dc }

  condition:
    any of them
}
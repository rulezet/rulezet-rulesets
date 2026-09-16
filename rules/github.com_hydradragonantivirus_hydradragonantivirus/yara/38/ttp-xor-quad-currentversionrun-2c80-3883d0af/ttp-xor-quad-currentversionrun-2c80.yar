rule TTP_XOR_QUAD_CurrentVersionRun_2c80 {
  strings:
    $key_2c80 = { 7f ef [2] 5b e1 [2] 70 cd [2] 5e ef [2] 4a f4 [2] 45 ee [2] 5b f3 [2] 59 f2 [2] 42 f4 [2] 5e f3 [2] 42 dc }

  condition:
    any of them
}
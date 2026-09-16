rule TTP_XOR_QUAD_CurrentVersionRun_2d80 {
  strings:
    $key_2d80 = { 7e ef [2] 5a e1 [2] 71 cd [2] 5f ef [2] 4b f4 [2] 44 ee [2] 5a f3 [2] 58 f2 [2] 43 f4 [2] 5f f3 [2] 43 dc }

  condition:
    any of them
}
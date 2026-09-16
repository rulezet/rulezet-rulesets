rule TTP_XOR_QUAD_CurrentVersionRun_fe80 {
  strings:
    $key_fe80 = { ad ef [2] 89 e1 [2] a2 cd [2] 8c ef [2] 98 f4 [2] 97 ee [2] 89 f3 [2] 8b f2 [2] 90 f4 [2] 8c f3 [2] 90 dc }

  condition:
    any of them
}
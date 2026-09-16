rule TTP_XOR_QUAD_CurrentVersionRun_3980 {
  strings:
    $key_3980 = { 6a ef [2] 4e e1 [2] 65 cd [2] 4b ef [2] 5f f4 [2] 50 ee [2] 4e f3 [2] 4c f2 [2] 57 f4 [2] 4b f3 [2] 57 dc }

  condition:
    any of them
}
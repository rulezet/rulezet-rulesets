rule TTP_XOR_QUAD_CurrentVersionRun_f980 {
  strings:
    $key_f980 = { aa ef [2] 8e e1 [2] a5 cd [2] 8b ef [2] 9f f4 [2] 90 ee [2] 8e f3 [2] 8c f2 [2] 97 f4 [2] 8b f3 [2] 97 dc }

  condition:
    any of them
}
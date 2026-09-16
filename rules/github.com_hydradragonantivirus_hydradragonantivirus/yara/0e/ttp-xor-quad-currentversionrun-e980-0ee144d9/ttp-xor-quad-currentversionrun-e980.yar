rule TTP_XOR_QUAD_CurrentVersionRun_e980 {
  strings:
    $key_e980 = { ba ef [2] 9e e1 [2] b5 cd [2] 9b ef [2] 8f f4 [2] 80 ee [2] 9e f3 [2] 9c f2 [2] 87 f4 [2] 9b f3 [2] 87 dc }

  condition:
    any of them
}
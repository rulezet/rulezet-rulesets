rule TTP_XOR_QUAD_CurrentVersionRun_e880 {
  strings:
    $key_e880 = { bb ef [2] 9f e1 [2] b4 cd [2] 9a ef [2] 8e f4 [2] 81 ee [2] 9f f3 [2] 9d f2 [2] 86 f4 [2] 9a f3 [2] 86 dc }

  condition:
    any of them
}
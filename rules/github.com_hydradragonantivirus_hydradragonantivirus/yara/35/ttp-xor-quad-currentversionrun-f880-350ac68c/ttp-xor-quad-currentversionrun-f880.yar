rule TTP_XOR_QUAD_CurrentVersionRun_f880 {
  strings:
    $key_f880 = { ab ef [2] 8f e1 [2] a4 cd [2] 8a ef [2] 9e f4 [2] 91 ee [2] 8f f3 [2] 8d f2 [2] 96 f4 [2] 8a f3 [2] 96 dc }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2280 {
  strings:
    $key_2280 = { 71 ef [2] 55 e1 [2] 7e cd [2] 50 ef [2] 44 f4 [2] 4b ee [2] 55 f3 [2] 57 f2 [2] 4c f4 [2] 50 f3 [2] 4c dc }

  condition:
    any of them
}
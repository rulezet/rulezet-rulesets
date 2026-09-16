rule TTP_XOR_QUAD_CurrentVersionRun_1280 {
  strings:
    $key_1280 = { 41 ef [2] 65 e1 [2] 4e cd [2] 60 ef [2] 74 f4 [2] 7b ee [2] 65 f3 [2] 67 f2 [2] 7c f4 [2] 60 f3 [2] 7c dc }

  condition:
    any of them
}
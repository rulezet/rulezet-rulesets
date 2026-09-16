rule TTP_XOR_QUAD_CurrentVersionRun_0280 {
  strings:
    $key_0280 = { 51 ef [2] 75 e1 [2] 5e cd [2] 70 ef [2] 64 f4 [2] 6b ee [2] 75 f3 [2] 77 f2 [2] 6c f4 [2] 70 f3 [2] 6c dc }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_f280 {
  strings:
    $key_f280 = { a1 ef [2] 85 e1 [2] ae cd [2] 80 ef [2] 94 f4 [2] 9b ee [2] 85 f3 [2] 87 f2 [2] 9c f4 [2] 80 f3 [2] 9c dc }

  condition:
    any of them
}
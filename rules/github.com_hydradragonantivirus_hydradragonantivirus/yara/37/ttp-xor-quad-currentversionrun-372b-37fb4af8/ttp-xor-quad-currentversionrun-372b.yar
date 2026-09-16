rule TTP_XOR_QUAD_CurrentVersionRun_372b {
  strings:
    $key_372b = { 64 44 [2] 40 4a [2] 6b 66 [2] 45 44 [2] 51 5f [2] 5e 45 [2] 40 58 [2] 42 59 [2] 59 5f [2] 45 58 [2] 59 77 }

  condition:
    any of them
}
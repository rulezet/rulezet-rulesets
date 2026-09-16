rule TTP_XOR_QUAD_CurrentVersionRun_70e0 {
  strings:
    $key_70e0 = { 23 8f [2] 07 81 [2] 2c ad [2] 02 8f [2] 16 94 [2] 19 8e [2] 07 93 [2] 05 92 [2] 1e 94 [2] 02 93 [2] 1e bc }

  condition:
    any of them
}
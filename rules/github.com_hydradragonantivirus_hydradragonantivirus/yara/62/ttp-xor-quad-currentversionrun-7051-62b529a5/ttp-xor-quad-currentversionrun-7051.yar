rule TTP_XOR_QUAD_CurrentVersionRun_7051 {
  strings:
    $key_7051 = { 23 3e [2] 07 30 [2] 2c 1c [2] 02 3e [2] 16 25 [2] 19 3f [2] 07 22 [2] 05 23 [2] 1e 25 [2] 02 22 [2] 1e 0d }

  condition:
    any of them
}
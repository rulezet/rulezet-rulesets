rule TTP_XOR_QUAD_CurrentVersionRun_5971 {
  strings:
    $key_5971 = { 0a 1e [2] 2e 10 [2] 05 3c [2] 2b 1e [2] 3f 05 [2] 30 1f [2] 2e 02 [2] 2c 03 [2] 37 05 [2] 2b 02 [2] 37 2d }

  condition:
    any of them
}
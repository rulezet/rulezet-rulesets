rule TTP_XOR_QUAD_CurrentVersionRun_0d42 {
  strings:
    $key_0d42 = { 5e 2d [2] 7a 23 [2] 51 0f [2] 7f 2d [2] 6b 36 [2] 64 2c [2] 7a 31 [2] 78 30 [2] 63 36 [2] 7f 31 [2] 63 1e }

  condition:
    any of them
}
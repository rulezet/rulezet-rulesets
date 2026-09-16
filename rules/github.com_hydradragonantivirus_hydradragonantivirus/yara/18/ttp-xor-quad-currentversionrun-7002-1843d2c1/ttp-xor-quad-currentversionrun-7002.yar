rule TTP_XOR_QUAD_CurrentVersionRun_7002 {
  strings:
    $key_7002 = { 23 6d [2] 07 63 [2] 2c 4f [2] 02 6d [2] 16 76 [2] 19 6c [2] 07 71 [2] 05 70 [2] 1e 76 [2] 02 71 [2] 1e 5e }

  condition:
    any of them
}
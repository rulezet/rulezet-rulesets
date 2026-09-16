rule TTP_XOR_QUAD_CurrentVersionRun_7f02 {
  strings:
    $key_7f02 = { 2c 6d [2] 08 63 [2] 23 4f [2] 0d 6d [2] 19 76 [2] 16 6c [2] 08 71 [2] 0a 70 [2] 11 76 [2] 0d 71 [2] 11 5e }

  condition:
    any of them
}
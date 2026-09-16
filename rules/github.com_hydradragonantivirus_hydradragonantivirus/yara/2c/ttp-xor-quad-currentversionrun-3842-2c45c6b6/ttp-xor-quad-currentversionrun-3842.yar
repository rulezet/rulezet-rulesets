rule TTP_XOR_QUAD_CurrentVersionRun_3842 {
  strings:
    $key_3842 = { 6b 2d [2] 4f 23 [2] 64 0f [2] 4a 2d [2] 5e 36 [2] 51 2c [2] 4f 31 [2] 4d 30 [2] 56 36 [2] 4a 31 [2] 56 1e }

  condition:
    any of them
}
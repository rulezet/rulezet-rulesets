rule TTP_XOR_QUAD_CurrentVersionRun_3f42 {
  strings:
    $key_3f42 = { 6c 2d [2] 48 23 [2] 63 0f [2] 4d 2d [2] 59 36 [2] 56 2c [2] 48 31 [2] 4a 30 [2] 51 36 [2] 4d 31 [2] 51 1e }

  condition:
    any of them
}
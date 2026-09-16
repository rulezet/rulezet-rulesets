rule TTP_XOR_QUAD_CurrentVersionRun_0a42 {
  strings:
    $key_0a42 = { 59 2d [2] 7d 23 [2] 56 0f [2] 78 2d [2] 6c 36 [2] 63 2c [2] 7d 31 [2] 7f 30 [2] 64 36 [2] 78 31 [2] 64 1e }

  condition:
    any of them
}
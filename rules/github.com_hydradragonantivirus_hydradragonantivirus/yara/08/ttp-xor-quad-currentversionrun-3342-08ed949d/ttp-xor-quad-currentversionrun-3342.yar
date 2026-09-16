rule TTP_XOR_QUAD_CurrentVersionRun_3342 {
  strings:
    $key_3342 = { 60 2d [2] 44 23 [2] 6f 0f [2] 41 2d [2] 55 36 [2] 5a 2c [2] 44 31 [2] 46 30 [2] 5d 36 [2] 41 31 [2] 5d 1e }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_4a31 {
  strings:
    $key_4a31 = { 19 5e [2] 3d 50 [2] 16 7c [2] 38 5e [2] 2c 45 [2] 23 5f [2] 3d 42 [2] 3f 43 [2] 24 45 [2] 38 42 [2] 24 6d }

  condition:
    any of them
}
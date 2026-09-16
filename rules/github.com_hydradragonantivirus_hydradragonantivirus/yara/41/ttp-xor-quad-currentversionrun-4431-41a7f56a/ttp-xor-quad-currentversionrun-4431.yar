rule TTP_XOR_QUAD_CurrentVersionRun_4431 {
  strings:
    $key_4431 = { 17 5e [2] 33 50 [2] 18 7c [2] 36 5e [2] 22 45 [2] 2d 5f [2] 33 42 [2] 31 43 [2] 2a 45 [2] 36 42 [2] 2a 6d }

  condition:
    any of them
}
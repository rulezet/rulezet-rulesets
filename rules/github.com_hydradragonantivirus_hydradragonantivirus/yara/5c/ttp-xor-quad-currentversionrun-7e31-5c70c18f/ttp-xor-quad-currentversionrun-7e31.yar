rule TTP_XOR_QUAD_CurrentVersionRun_7e31 {
  strings:
    $key_7e31 = { 2d 5e [2] 09 50 [2] 22 7c [2] 0c 5e [2] 18 45 [2] 17 5f [2] 09 42 [2] 0b 43 [2] 10 45 [2] 0c 42 [2] 10 6d }

  condition:
    any of them
}
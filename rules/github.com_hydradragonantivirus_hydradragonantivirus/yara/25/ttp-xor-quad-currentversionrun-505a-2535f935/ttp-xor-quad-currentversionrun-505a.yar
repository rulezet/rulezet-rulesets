rule TTP_XOR_QUAD_CurrentVersionRun_505a {
  strings:
    $key_505a = { 03 35 [2] 27 3b [2] 0c 17 [2] 22 35 [2] 36 2e [2] 39 34 [2] 27 29 [2] 25 28 [2] 3e 2e [2] 22 29 [2] 3e 06 }

  condition:
    any of them
}
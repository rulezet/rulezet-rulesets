rule TTP_XOR_QUAD_CurrentVersionRun_3551 {
  strings:
    $key_3551 = { 66 3e [2] 42 30 [2] 69 1c [2] 47 3e [2] 53 25 [2] 5c 3f [2] 42 22 [2] 40 23 [2] 5b 25 [2] 47 22 [2] 5b 0d }

  condition:
    any of them
}
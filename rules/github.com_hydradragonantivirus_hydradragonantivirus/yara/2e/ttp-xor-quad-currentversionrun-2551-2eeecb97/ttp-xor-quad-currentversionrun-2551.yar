rule TTP_XOR_QUAD_CurrentVersionRun_2551 {
  strings:
    $key_2551 = { 76 3e [2] 52 30 [2] 79 1c [2] 57 3e [2] 43 25 [2] 4c 3f [2] 52 22 [2] 50 23 [2] 4b 25 [2] 57 22 [2] 4b 0d }

  condition:
    any of them
}
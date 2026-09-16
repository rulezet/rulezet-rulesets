rule TTP_XOR_QUAD_CurrentVersionRun_1b51 {
  strings:
    $key_1b51 = { 48 3e [2] 6c 30 [2] 47 1c [2] 69 3e [2] 7d 25 [2] 72 3f [2] 6c 22 [2] 6e 23 [2] 75 25 [2] 69 22 [2] 75 0d }

  condition:
    any of them
}
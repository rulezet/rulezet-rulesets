rule TTP_XOR_QUAD_CurrentVersionRun_2a51 {
  strings:
    $key_2a51 = { 79 3e [2] 5d 30 [2] 76 1c [2] 58 3e [2] 4c 25 [2] 43 3f [2] 5d 22 [2] 5f 23 [2] 44 25 [2] 58 22 [2] 44 0d }

  condition:
    any of them
}
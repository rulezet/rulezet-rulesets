rule TTP_XOR_QUAD_CurrentVersionRun_2f51 {
  strings:
    $key_2f51 = { 7c 3e [2] 58 30 [2] 73 1c [2] 5d 3e [2] 49 25 [2] 46 3f [2] 58 22 [2] 5a 23 [2] 41 25 [2] 5d 22 [2] 41 0d }

  condition:
    any of them
}
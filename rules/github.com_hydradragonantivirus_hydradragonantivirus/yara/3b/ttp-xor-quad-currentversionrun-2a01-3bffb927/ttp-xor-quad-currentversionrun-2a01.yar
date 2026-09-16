rule TTP_XOR_QUAD_CurrentVersionRun_2a01 {
  strings:
    $key_2a01 = { 79 6e [2] 5d 60 [2] 76 4c [2] 58 6e [2] 4c 75 [2] 43 6f [2] 5d 72 [2] 5f 73 [2] 44 75 [2] 58 72 [2] 44 5d }

  condition:
    any of them
}
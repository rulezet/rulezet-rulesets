rule TTP_XOR_QUAD_CurrentVersionRun_2af7 {
  strings:
    $key_2af7 = { 79 98 [2] 5d 96 [2] 76 ba [2] 58 98 [2] 4c 83 [2] 43 99 [2] 5d 84 [2] 5f 85 [2] 44 83 [2] 58 84 [2] 44 ab }

  condition:
    any of them
}
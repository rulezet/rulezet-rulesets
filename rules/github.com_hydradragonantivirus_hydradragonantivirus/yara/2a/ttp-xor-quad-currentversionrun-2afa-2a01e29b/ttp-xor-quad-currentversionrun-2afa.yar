rule TTP_XOR_QUAD_CurrentVersionRun_2afa {
  strings:
    $key_2afa = { 79 95 [2] 5d 9b [2] 76 b7 [2] 58 95 [2] 4c 8e [2] 43 94 [2] 5d 89 [2] 5f 88 [2] 44 8e [2] 58 89 [2] 44 a6 }

  condition:
    any of them
}
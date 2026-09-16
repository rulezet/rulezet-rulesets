rule TTP_XOR_QUAD_CurrentVersionRun_3efa {
  strings:
    $key_3efa = { 6d 95 [2] 49 9b [2] 62 b7 [2] 4c 95 [2] 58 8e [2] 57 94 [2] 49 89 [2] 4b 88 [2] 50 8e [2] 4c 89 [2] 50 a6 }

  condition:
    any of them
}
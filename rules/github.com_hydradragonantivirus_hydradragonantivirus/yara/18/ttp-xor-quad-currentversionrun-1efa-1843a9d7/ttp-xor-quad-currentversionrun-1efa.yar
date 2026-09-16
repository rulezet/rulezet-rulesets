rule TTP_XOR_QUAD_CurrentVersionRun_1efa {
  strings:
    $key_1efa = { 4d 95 [2] 69 9b [2] 42 b7 [2] 6c 95 [2] 78 8e [2] 77 94 [2] 69 89 [2] 6b 88 [2] 70 8e [2] 6c 89 [2] 70 a6 }

  condition:
    any of them
}
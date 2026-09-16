rule TTP_XOR_QUAD_CurrentVersionRun_2efa {
  strings:
    $key_2efa = { 7d 95 [2] 59 9b [2] 72 b7 [2] 5c 95 [2] 48 8e [2] 47 94 [2] 59 89 [2] 5b 88 [2] 40 8e [2] 5c 89 [2] 40 a6 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_7afa {
  strings:
    $key_7afa = { 29 95 [2] 0d 9b [2] 26 b7 [2] 08 95 [2] 1c 8e [2] 13 94 [2] 0d 89 [2] 0f 88 [2] 14 8e [2] 08 89 [2] 14 a6 }

  condition:
    any of them
}
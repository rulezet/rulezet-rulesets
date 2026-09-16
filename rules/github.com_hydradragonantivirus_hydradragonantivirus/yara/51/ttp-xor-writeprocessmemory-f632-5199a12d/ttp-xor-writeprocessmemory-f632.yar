rule TTP_XOR_WriteProcessMemory_f632 {
  strings:
    $key_f632 = { a1 40 [2] 93 62 [2] 95 57 [2] bb 57 [2] 84 4b }

  condition:
    any of them
}
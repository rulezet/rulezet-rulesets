rule TTP_XOR_WriteProcessMemory_ecbe {
  strings:
    $key_ecbe = { bb cc [2] 89 ee [2] 8f db [2] a1 db [2] 9e c7 }

  condition:
    any of them
}
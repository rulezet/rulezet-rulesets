rule TTP_XOR_WriteProcessMemory_f6ed {
  strings:
    $key_f6ed = { a1 9f [2] 93 bd [2] 95 88 [2] bb 88 [2] 84 94 }

  condition:
    any of them
}
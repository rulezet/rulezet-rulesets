rule TTP_XOR_WriteProcessMemory_f6f4 {
  strings:
    $key_f6f4 = { a1 86 [2] 93 a4 [2] 95 91 [2] bb 91 [2] 84 8d }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_f6e3 {
  strings:
    $key_f6e3 = { a1 91 [2] 93 b3 [2] 95 86 [2] bb 86 [2] 84 9a }

  condition:
    any of them
}
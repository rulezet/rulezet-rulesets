rule TTP_XOR_WriteProcessMemory_f611 {
  strings:
    $key_f611 = { a1 63 [2] 93 41 [2] 95 74 [2] bb 74 [2] 84 68 }

  condition:
    any of them
}
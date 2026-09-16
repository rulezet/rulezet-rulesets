rule TTP_XOR_WriteProcessMemory_e4f9 {
  strings:
    $key_e4f9 = { b3 8b [2] 81 a9 [2] 87 9c [2] a9 9c [2] 96 80 }

  condition:
    any of them
}
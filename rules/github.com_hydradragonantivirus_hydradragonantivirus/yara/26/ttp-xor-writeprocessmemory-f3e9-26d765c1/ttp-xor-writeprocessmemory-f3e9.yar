rule TTP_XOR_WriteProcessMemory_f3e9 {
  strings:
    $key_f3e9 = { a4 9b [2] 96 b9 [2] 90 8c [2] be 8c [2] 81 90 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_27f8 {
  strings:
    $key_27f8 = { 70 8a [2] 42 a8 [2] 44 9d [2] 6a 9d [2] 55 81 }

  condition:
    any of them
}
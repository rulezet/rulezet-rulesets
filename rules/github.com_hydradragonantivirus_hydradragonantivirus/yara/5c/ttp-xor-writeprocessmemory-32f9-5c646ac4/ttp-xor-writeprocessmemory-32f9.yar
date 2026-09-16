rule TTP_XOR_WriteProcessMemory_32f9 {
  strings:
    $key_32f9 = { 65 8b [2] 57 a9 [2] 51 9c [2] 7f 9c [2] 40 80 }

  condition:
    any of them
}
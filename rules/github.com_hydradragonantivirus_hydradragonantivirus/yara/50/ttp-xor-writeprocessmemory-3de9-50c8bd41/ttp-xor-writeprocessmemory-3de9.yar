rule TTP_XOR_WriteProcessMemory_3de9 {
  strings:
    $key_3de9 = { 6a 9b [2] 58 b9 [2] 5e 8c [2] 70 8c [2] 4f 90 }

  condition:
    any of them
}
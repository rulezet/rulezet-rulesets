rule TTP_XOR_WriteProcessMemory_2af9 {
  strings:
    $key_2af9 = { 7d 8b [2] 4f a9 [2] 49 9c [2] 67 9c [2] 58 80 }

  condition:
    any of them
}
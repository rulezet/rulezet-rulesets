rule TTP_XOR_WriteProcessMemory_1ae9 {
  strings:
    $key_1ae9 = { 4d 9b [2] 7f b9 [2] 79 8c [2] 57 8c [2] 68 90 }

  condition:
    any of them
}
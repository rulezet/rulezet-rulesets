rule TTP_XOR_WriteProcessMemory_1ef9 {
  strings:
    $key_1ef9 = { 49 8b [2] 7b a9 [2] 7d 9c [2] 53 9c [2] 6c 80 }

  condition:
    any of them
}
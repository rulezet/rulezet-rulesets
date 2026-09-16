rule TTP_XOR_WriteProcessMemory_2ef9 {
  strings:
    $key_2ef9 = { 79 8b [2] 4b a9 [2] 4d 9c [2] 63 9c [2] 5c 80 }

  condition:
    any of them
}
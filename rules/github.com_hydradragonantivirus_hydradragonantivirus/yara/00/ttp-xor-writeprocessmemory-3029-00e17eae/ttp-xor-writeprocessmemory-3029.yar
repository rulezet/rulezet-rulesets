rule TTP_XOR_WriteProcessMemory_3029 {
  strings:
    $key_3029 = { 67 5b [2] 55 79 [2] 53 4c [2] 7d 4c [2] 42 50 }

  condition:
    any of them
}
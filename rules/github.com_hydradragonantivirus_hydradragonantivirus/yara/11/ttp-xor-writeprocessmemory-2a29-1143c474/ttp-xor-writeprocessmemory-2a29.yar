rule TTP_XOR_WriteProcessMemory_2a29 {
  strings:
    $key_2a29 = { 7d 5b [2] 4f 79 [2] 49 4c [2] 67 4c [2] 58 50 }

  condition:
    any of them
}
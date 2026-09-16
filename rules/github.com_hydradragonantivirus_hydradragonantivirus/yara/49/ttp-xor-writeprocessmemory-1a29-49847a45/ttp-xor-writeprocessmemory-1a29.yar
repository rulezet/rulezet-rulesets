rule TTP_XOR_WriteProcessMemory_1a29 {
  strings:
    $key_1a29 = { 4d 5b [2] 7f 79 [2] 79 4c [2] 57 4c [2] 68 50 }

  condition:
    any of them
}
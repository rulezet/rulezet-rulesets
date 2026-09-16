rule TTP_XOR_WriteProcessMemory_6e29 {
  strings:
    $key_6e29 = { 39 5b [2] 0b 79 [2] 0d 4c [2] 23 4c [2] 1c 50 }

  condition:
    any of them
}
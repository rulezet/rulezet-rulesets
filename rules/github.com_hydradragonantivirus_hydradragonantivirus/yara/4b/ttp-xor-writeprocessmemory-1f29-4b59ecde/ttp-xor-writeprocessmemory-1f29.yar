rule TTP_XOR_WriteProcessMemory_1f29 {
  strings:
    $key_1f29 = { 48 5b [2] 7a 79 [2] 7c 4c [2] 52 4c [2] 6d 50 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_3f29 {
  strings:
    $key_3f29 = { 68 5b [2] 5a 79 [2] 5c 4c [2] 72 4c [2] 4d 50 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_0a29 {
  strings:
    $key_0a29 = { 5d 5b [2] 6f 79 [2] 69 4c [2] 47 4c [2] 78 50 }

  condition:
    any of them
}
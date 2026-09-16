rule TTP_XOR_WriteProcessMemory_5829 {
  strings:
    $key_5829 = { 0f 5b [2] 3d 79 [2] 3b 4c [2] 15 4c [2] 2a 50 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_5840 {
  strings:
    $key_5840 = { 0f 32 [2] 3d 10 [2] 3b 25 [2] 15 25 [2] 2a 39 }

  condition:
    any of them
}
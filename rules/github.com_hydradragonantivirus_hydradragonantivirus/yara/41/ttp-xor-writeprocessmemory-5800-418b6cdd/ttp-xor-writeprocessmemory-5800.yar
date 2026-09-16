rule TTP_XOR_WriteProcessMemory_5800 {
  strings:
    $key_5800 = { 0f 72 [2] 3d 50 [2] 3b 65 [2] 15 65 [2] 2a 79 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_5802 {
  strings:
    $key_5802 = { 0f 70 [2] 3d 52 [2] 3b 67 [2] 15 67 [2] 2a 7b }

  condition:
    any of them
}
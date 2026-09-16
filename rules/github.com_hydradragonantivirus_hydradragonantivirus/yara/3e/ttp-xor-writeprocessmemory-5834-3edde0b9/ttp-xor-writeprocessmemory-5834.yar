rule TTP_XOR_WriteProcessMemory_5834 {
  strings:
    $key_5834 = { 0f 46 [2] 3d 64 [2] 3b 51 [2] 15 51 [2] 2a 4d }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_1834 {
  strings:
    $key_1834 = { 4f 46 [2] 7d 64 [2] 7b 51 [2] 55 51 [2] 6a 4d }

  condition:
    any of them
}
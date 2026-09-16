rule TTP_XOR_WriteProcessMemory_0a46 {
  strings:
    $key_0a46 = { 5d 34 [2] 6f 16 [2] 69 23 [2] 47 23 [2] 78 3f }

  condition:
    any of them
}
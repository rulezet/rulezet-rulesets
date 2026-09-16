rule TTP_XOR_WriteProcessMemory_18c4 {
  strings:
    $key_18c4 = { 4f b6 [2] 7d 94 [2] 7b a1 [2] 55 a1 [2] 6a bd }

  condition:
    any of them
}
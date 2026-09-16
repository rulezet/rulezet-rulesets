rule TTP_XOR_WriteProcessMemory_38c4 {
  strings:
    $key_38c4 = { 6f b6 [2] 5d 94 [2] 5b a1 [2] 75 a1 [2] 4a bd }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_0af7 {
  strings:
    $key_0af7 = { 5d 85 [2] 6f a7 [2] 69 92 [2] 47 92 [2] 78 8e }

  condition:
    any of them
}
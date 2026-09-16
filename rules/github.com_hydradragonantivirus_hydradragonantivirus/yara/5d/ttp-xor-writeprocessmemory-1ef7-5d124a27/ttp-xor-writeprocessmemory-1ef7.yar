rule TTP_XOR_WriteProcessMemory_1ef7 {
  strings:
    $key_1ef7 = { 49 85 [2] 7b a7 [2] 7d 92 [2] 53 92 [2] 6c 8e }

  condition:
    any of them
}
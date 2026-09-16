rule TTP_XOR_WriteProcessMemory_0ef7 {
  strings:
    $key_0ef7 = { 59 85 [2] 6b a7 [2] 6d 92 [2] 43 92 [2] 7c 8e }

  condition:
    any of them
}
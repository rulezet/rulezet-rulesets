rule TTP_XOR_WriteProcessMemory_4ef7 {
  strings:
    $key_4ef7 = { 19 85 [2] 2b a7 [2] 2d 92 [2] 03 92 [2] 3c 8e }

  condition:
    any of them
}
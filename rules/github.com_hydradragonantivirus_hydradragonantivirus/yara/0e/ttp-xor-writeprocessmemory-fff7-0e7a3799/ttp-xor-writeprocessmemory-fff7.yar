rule TTP_XOR_WriteProcessMemory_fff7 {
  strings:
    $key_fff7 = { a8 85 [2] 9a a7 [2] 9c 92 [2] b2 92 [2] 8d 8e }

  condition:
    any of them
}
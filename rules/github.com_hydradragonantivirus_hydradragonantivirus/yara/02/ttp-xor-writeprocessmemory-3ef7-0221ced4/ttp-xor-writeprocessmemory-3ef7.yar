rule TTP_XOR_WriteProcessMemory_3ef7 {
  strings:
    $key_3ef7 = { 69 85 [2] 5b a7 [2] 5d 92 [2] 73 92 [2] 4c 8e }

  condition:
    any of them
}
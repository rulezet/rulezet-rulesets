rule TTP_XOR_WriteProcessMemory_39f7 {
  strings:
    $key_39f7 = { 6e 85 [2] 5c a7 [2] 5a 92 [2] 74 92 [2] 4b 8e }

  condition:
    any of them
}
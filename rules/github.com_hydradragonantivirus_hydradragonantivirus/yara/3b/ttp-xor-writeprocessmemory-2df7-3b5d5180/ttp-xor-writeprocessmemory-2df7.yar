rule TTP_XOR_WriteProcessMemory_2df7 {
  strings:
    $key_2df7 = { 7a 85 [2] 48 a7 [2] 4e 92 [2] 60 92 [2] 5f 8e }

  condition:
    any of them
}
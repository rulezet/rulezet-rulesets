rule TTP_XOR_WriteProcessMemory_29f7 {
  strings:
    $key_29f7 = { 7e 85 [2] 4c a7 [2] 4a 92 [2] 64 92 [2] 5b 8e }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_0977 {
  strings:
    $key_0977 = { 5e 05 [2] 6c 27 [2] 6a 12 [2] 44 12 [2] 7b 0e }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_4163 {
  strings:
    $key_4163 = { 16 11 [2] 24 33 [2] 22 06 [2] 0c 06 [2] 33 1a }

  condition:
    any of them
}
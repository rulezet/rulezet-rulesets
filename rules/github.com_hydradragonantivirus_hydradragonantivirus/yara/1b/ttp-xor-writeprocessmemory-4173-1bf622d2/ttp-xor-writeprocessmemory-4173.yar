rule TTP_XOR_WriteProcessMemory_4173 {
  strings:
    $key_4173 = { 16 01 [2] 24 23 [2] 22 16 [2] 0c 16 [2] 33 0a }

  condition:
    any of them
}
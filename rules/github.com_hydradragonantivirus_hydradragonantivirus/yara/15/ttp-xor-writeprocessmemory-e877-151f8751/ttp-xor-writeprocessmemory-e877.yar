rule TTP_XOR_WriteProcessMemory_e877 {
  strings:
    $key_e877 = { bf 05 [2] 8d 27 [2] 8b 12 [2] a5 12 [2] 9a 0e }

  condition:
    any of them
}
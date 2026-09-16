rule TTP_XOR_WriteProcessMemory_2502 {
  strings:
    $key_2502 = { 72 70 [2] 40 52 [2] 46 67 [2] 68 67 [2] 57 7b }

  condition:
    any of them
}
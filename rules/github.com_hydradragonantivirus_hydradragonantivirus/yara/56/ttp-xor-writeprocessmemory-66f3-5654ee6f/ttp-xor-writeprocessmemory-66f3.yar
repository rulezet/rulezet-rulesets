rule TTP_XOR_WriteProcessMemory_66f3 {
  strings:
    $key_66f3 = { 31 81 [2] 03 a3 [2] 05 96 [2] 2b 96 [2] 14 8a }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_3bf3 {
  strings:
    $key_3bf3 = { 6c 81 [2] 5e a3 [2] 58 96 [2] 76 96 [2] 49 8a }

  condition:
    any of them
}
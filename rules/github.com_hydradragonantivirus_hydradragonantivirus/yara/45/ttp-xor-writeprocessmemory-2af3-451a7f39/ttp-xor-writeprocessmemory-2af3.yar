rule TTP_XOR_WriteProcessMemory_2af3 {
  strings:
    $key_2af3 = { 7d 81 [2] 4f a3 [2] 49 96 [2] 67 96 [2] 58 8a }

  condition:
    any of them
}
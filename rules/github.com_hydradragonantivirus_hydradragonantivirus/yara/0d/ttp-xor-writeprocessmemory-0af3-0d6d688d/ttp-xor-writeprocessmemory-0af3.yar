rule TTP_XOR_WriteProcessMemory_0af3 {
  strings:
    $key_0af3 = { 5d 81 [2] 6f a3 [2] 69 96 [2] 47 96 [2] 78 8a }

  condition:
    any of them
}
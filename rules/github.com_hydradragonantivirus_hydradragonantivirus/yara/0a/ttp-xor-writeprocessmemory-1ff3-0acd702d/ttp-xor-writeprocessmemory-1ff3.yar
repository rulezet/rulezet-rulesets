rule TTP_XOR_WriteProcessMemory_1ff3 {
  strings:
    $key_1ff3 = { 48 81 [2] 7a a3 [2] 7c 96 [2] 52 96 [2] 6d 8a }

  condition:
    any of them
}
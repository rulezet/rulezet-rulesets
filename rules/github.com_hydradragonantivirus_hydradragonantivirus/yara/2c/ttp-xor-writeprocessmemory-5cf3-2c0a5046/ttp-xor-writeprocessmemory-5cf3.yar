rule TTP_XOR_WriteProcessMemory_5cf3 {
  strings:
    $key_5cf3 = { 0b 81 [2] 39 a3 [2] 3f 96 [2] 11 96 [2] 2e 8a }

  condition:
    any of them
}
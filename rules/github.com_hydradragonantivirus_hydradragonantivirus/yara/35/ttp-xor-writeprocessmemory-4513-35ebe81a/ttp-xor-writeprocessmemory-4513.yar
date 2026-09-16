rule TTP_XOR_WriteProcessMemory_4513 {
  strings:
    $key_4513 = { 12 61 [2] 20 43 [2] 26 76 [2] 08 76 [2] 37 6a }

  condition:
    any of them
}
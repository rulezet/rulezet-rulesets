rule TTP_XOR_WriteProcessMemory_1753 {
  strings:
    $key_1753 = { 40 21 [2] 72 03 [2] 74 36 [2] 5a 36 [2] 65 2a }

  condition:
    any of them
}
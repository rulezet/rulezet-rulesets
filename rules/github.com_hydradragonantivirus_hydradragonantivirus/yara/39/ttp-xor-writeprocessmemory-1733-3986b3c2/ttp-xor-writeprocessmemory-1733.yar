rule TTP_XOR_WriteProcessMemory_1733 {
  strings:
    $key_1733 = { 40 41 [2] 72 63 [2] 74 56 [2] 5a 56 [2] 65 4a }

  condition:
    any of them
}
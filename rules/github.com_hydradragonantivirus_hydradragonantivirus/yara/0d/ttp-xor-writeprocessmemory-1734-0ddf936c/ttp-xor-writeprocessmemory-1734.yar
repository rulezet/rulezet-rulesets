rule TTP_XOR_WriteProcessMemory_1734 {
  strings:
    $key_1734 = { 40 46 [2] 72 64 [2] 74 51 [2] 5a 51 [2] 65 4d }

  condition:
    any of them
}
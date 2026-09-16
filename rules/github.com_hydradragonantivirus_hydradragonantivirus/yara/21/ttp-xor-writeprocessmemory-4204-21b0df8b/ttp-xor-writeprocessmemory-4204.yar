rule TTP_XOR_WriteProcessMemory_4204 {
  strings:
    $key_4204 = { 15 76 [2] 27 54 [2] 21 61 [2] 0f 61 [2] 30 7d }

  condition:
    any of them
}
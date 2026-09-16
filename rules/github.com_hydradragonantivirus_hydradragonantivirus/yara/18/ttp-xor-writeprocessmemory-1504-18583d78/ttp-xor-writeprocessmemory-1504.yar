rule TTP_XOR_WriteProcessMemory_1504 {
  strings:
    $key_1504 = { 42 76 [2] 70 54 [2] 76 61 [2] 58 61 [2] 67 7d }

  condition:
    any of them
}
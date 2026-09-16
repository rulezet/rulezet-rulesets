rule TTP_XOR_WriteProcessMemory_1d04 {
  strings:
    $key_1d04 = { 4a 76 [2] 78 54 [2] 7e 61 [2] 50 61 [2] 6f 7d }

  condition:
    any of them
}
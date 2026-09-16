rule TTP_XOR_WriteProcessMemory_7802 {
  strings:
    $key_7802 = { 2f 70 [2] 1d 52 [2] 1b 67 [2] 35 67 [2] 0a 7b }

  condition:
    any of them
}
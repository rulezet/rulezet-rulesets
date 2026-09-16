rule TTP_XOR_WriteProcessMemory_7143 {
  strings:
    $key_7143 = { 26 31 [2] 14 13 [2] 12 26 [2] 3c 26 [2] 03 3a }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_7122 {
  strings:
    $key_7122 = { 26 50 [2] 14 72 [2] 12 47 [2] 3c 47 [2] 03 5b }

  condition:
    any of them
}
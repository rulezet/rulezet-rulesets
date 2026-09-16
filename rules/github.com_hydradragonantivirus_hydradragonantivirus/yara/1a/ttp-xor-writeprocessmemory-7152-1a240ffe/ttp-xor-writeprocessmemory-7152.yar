rule TTP_XOR_WriteProcessMemory_7152 {
  strings:
    $key_7152 = { 26 20 [2] 14 02 [2] 12 37 [2] 3c 37 [2] 03 2b }

  condition:
    any of them
}
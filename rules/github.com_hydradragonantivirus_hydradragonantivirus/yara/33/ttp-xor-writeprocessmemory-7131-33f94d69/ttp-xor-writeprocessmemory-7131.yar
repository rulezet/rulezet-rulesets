rule TTP_XOR_WriteProcessMemory_7131 {
  strings:
    $key_7131 = { 26 43 [2] 14 61 [2] 12 54 [2] 3c 54 [2] 03 48 }

  condition:
    any of them
}
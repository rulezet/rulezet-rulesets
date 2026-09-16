rule TTP_XOR_WriteProcessMemory_7117 {
  strings:
    $key_7117 = { 26 65 [2] 14 47 [2] 12 72 [2] 3c 72 [2] 03 6e }

  condition:
    any of them
}
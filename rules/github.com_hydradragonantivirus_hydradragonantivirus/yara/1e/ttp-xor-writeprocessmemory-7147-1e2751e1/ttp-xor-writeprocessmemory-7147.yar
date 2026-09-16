rule TTP_XOR_WriteProcessMemory_7147 {
  strings:
    $key_7147 = { 26 35 [2] 14 17 [2] 12 22 [2] 3c 22 [2] 03 3e }

  condition:
    any of them
}
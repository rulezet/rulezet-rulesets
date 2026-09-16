rule TTP_XOR_WriteProcessMemory_7104 {
  strings:
    $key_7104 = { 26 76 [2] 14 54 [2] 12 61 [2] 3c 61 [2] 03 7d }

  condition:
    any of them
}
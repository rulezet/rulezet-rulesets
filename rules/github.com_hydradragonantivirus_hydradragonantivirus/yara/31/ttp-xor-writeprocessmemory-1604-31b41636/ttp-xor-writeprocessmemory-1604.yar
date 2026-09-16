rule TTP_XOR_WriteProcessMemory_1604 {
  strings:
    $key_1604 = { 41 76 [2] 73 54 [2] 75 61 [2] 5b 61 [2] 64 7d }

  condition:
    any of them
}
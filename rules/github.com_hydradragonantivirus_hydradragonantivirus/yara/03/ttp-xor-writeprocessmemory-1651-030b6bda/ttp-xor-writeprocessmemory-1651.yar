rule TTP_XOR_WriteProcessMemory_1651 {
  strings:
    $key_1651 = { 41 23 [2] 73 01 [2] 75 34 [2] 5b 34 [2] 64 28 }

  condition:
    any of them
}
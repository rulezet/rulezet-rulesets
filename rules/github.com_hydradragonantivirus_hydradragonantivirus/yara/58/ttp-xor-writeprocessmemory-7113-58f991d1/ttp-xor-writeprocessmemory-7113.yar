rule TTP_XOR_WriteProcessMemory_7113 {
  strings:
    $key_7113 = { 26 61 [2] 14 43 [2] 12 76 [2] 3c 76 [2] 03 6a }

  condition:
    any of them
}
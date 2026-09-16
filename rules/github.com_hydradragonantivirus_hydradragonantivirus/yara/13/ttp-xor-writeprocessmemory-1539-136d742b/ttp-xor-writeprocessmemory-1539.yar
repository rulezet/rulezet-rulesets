rule TTP_XOR_WriteProcessMemory_1539 {
  strings:
    $key_1539 = { 42 4b [2] 70 69 [2] 76 5c [2] 58 5c [2] 67 40 }

  condition:
    any of them
}
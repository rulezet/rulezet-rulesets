rule TTP_XOR_WriteProcessMemory_1951 {
  strings:
    $key_1951 = { 4e 23 [2] 7c 01 [2] 7a 34 [2] 54 34 [2] 6b 28 }

  condition:
    any of them
}
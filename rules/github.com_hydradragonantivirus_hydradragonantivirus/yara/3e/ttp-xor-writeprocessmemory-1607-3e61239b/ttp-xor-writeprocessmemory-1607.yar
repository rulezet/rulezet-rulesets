rule TTP_XOR_WriteProcessMemory_1607 {
  strings:
    $key_1607 = { 41 75 [2] 73 57 [2] 75 62 [2] 5b 62 [2] 64 7e }

  condition:
    any of them
}
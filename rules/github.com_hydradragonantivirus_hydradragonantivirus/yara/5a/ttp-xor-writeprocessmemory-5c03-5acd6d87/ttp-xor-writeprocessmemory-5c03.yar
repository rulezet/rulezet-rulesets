rule TTP_XOR_WriteProcessMemory_5c03 {
  strings:
    $key_5c03 = { 0b 71 [2] 39 53 [2] 3f 66 [2] 11 66 [2] 2e 7a }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_5c53 {
  strings:
    $key_5c53 = { 0b 21 [2] 39 03 [2] 3f 36 [2] 11 36 [2] 2e 2a }

  condition:
    any of them
}
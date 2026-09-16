rule TTP_XOR_WriteProcessMemory_5c30 {
  strings:
    $key_5c30 = { 0b 42 [2] 39 60 [2] 3f 55 [2] 11 55 [2] 2e 49 }

  condition:
    any of them
}
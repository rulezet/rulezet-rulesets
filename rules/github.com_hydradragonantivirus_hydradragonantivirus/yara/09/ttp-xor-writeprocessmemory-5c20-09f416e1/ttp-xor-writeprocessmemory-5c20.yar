rule TTP_XOR_WriteProcessMemory_5c20 {
  strings:
    $key_5c20 = { 0b 52 [2] 39 70 [2] 3f 45 [2] 11 45 [2] 2e 59 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_7200 {
  strings:
    $key_7200 = { 25 72 [2] 17 50 [2] 11 65 [2] 3f 65 [2] 00 79 }

  condition:
    any of them
}
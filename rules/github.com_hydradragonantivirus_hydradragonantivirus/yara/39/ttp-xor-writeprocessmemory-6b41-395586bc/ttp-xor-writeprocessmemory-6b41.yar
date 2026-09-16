rule TTP_XOR_WriteProcessMemory_6b41 {
  strings:
    $key_6b41 = { 3c 33 [2] 0e 11 [2] 08 24 [2] 26 24 [2] 19 38 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_6d41 {
  strings:
    $key_6d41 = { 3a 33 [2] 08 11 [2] 0e 24 [2] 20 24 [2] 1f 38 }

  condition:
    any of them
}
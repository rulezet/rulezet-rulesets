rule TTP_XOR_WriteProcessMemory_6d40 {
  strings:
    $key_6d40 = { 3a 32 [2] 08 10 [2] 0e 25 [2] 20 25 [2] 1f 39 }

  condition:
    any of them
}
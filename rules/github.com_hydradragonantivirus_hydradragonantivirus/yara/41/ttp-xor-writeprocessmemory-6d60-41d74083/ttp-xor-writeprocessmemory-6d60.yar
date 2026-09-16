rule TTP_XOR_WriteProcessMemory_6d60 {
  strings:
    $key_6d60 = { 3a 12 [2] 08 30 [2] 0e 05 [2] 20 05 [2] 1f 19 }

  condition:
    any of them
}
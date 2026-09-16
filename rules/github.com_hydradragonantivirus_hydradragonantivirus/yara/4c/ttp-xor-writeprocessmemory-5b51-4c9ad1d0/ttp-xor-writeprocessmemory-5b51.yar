rule TTP_XOR_WriteProcessMemory_5b51 {
  strings:
    $key_5b51 = { 0c 23 [2] 3e 01 [2] 38 34 [2] 16 34 [2] 29 28 }

  condition:
    any of them
}
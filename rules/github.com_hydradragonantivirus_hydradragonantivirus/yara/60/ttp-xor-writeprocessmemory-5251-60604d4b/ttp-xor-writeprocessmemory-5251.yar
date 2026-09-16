rule TTP_XOR_WriteProcessMemory_5251 {
  strings:
    $key_5251 = { 05 23 [2] 37 01 [2] 31 34 [2] 1f 34 [2] 20 28 }

  condition:
    any of them
}
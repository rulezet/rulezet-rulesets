rule TTP_XOR_WriteProcessMemory_4551 {
  strings:
    $key_4551 = { 12 23 [2] 20 01 [2] 26 34 [2] 08 34 [2] 37 28 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_5551 {
  strings:
    $key_5551 = { 02 23 [2] 30 01 [2] 36 34 [2] 18 34 [2] 27 28 }

  condition:
    any of them
}
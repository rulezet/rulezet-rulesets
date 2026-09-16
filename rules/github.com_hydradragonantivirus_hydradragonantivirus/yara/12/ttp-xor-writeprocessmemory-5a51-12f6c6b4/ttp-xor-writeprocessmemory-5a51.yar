rule TTP_XOR_WriteProcessMemory_5a51 {
  strings:
    $key_5a51 = { 0d 23 [2] 3f 01 [2] 39 34 [2] 17 34 [2] 28 28 }

  condition:
    any of them
}
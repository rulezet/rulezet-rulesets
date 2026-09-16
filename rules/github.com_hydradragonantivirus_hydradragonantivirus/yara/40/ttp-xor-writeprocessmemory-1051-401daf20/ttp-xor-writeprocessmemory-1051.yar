rule TTP_XOR_WriteProcessMemory_1051 {
  strings:
    $key_1051 = { 47 23 [2] 75 01 [2] 73 34 [2] 5d 34 [2] 62 28 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_6200 {
  strings:
    $key_6200 = { 35 72 [2] 07 50 [2] 01 65 [2] 2f 65 [2] 10 79 }

  condition:
    any of them
}
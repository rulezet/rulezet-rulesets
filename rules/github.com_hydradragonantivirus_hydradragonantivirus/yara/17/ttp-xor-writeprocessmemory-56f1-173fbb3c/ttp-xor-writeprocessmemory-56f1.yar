rule TTP_XOR_WriteProcessMemory_56f1 {
  strings:
    $key_56f1 = { 01 83 [2] 33 a1 [2] 35 94 [2] 1b 94 [2] 24 88 }

  condition:
    any of them
}
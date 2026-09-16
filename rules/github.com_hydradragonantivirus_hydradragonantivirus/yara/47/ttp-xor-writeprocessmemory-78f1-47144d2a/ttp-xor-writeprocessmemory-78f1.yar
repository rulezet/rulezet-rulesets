rule TTP_XOR_WriteProcessMemory_78f1 {
  strings:
    $key_78f1 = { 2f 83 [2] 1d a1 [2] 1b 94 [2] 35 94 [2] 0a 88 }

  condition:
    any of them
}
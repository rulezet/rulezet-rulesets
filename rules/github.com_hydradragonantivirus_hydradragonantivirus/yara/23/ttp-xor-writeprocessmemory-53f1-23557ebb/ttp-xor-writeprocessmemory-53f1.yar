rule TTP_XOR_WriteProcessMemory_53f1 {
  strings:
    $key_53f1 = { 04 83 [2] 36 a1 [2] 30 94 [2] 1e 94 [2] 21 88 }

  condition:
    any of them
}
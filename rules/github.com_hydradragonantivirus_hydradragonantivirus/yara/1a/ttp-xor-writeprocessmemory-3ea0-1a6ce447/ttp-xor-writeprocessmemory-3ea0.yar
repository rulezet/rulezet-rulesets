rule TTP_XOR_WriteProcessMemory_3ea0 {
  strings:
    $key_3ea0 = { 69 d2 [2] 5b f0 [2] 5d c5 [2] 73 c5 [2] 4c d9 }

  condition:
    any of them
}
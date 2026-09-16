rule TTP_XOR_WriteProcessMemory_6ea0 {
  strings:
    $key_6ea0 = { 39 d2 [2] 0b f0 [2] 0d c5 [2] 23 c5 [2] 1c d9 }

  condition:
    any of them
}
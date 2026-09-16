rule TTP_XOR_WriteProcessMemory_0ea0 {
  strings:
    $key_0ea0 = { 59 d2 [2] 6b f0 [2] 6d c5 [2] 43 c5 [2] 7c d9 }

  condition:
    any of them
}
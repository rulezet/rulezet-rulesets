rule TTP_XOR_WriteProcessMemory_eea0 {
  strings:
    $key_eea0 = { b9 d2 [2] 8b f0 [2] 8d c5 [2] a3 c5 [2] 9c d9 }

  condition:
    any of them
}
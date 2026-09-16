rule TTP_XOR_WriteProcessMemory_38a0 {
  strings:
    $key_38a0 = { 6f d2 [2] 5d f0 [2] 5b c5 [2] 75 c5 [2] 4a d9 }

  condition:
    any of them
}
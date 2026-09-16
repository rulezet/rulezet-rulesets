rule TTP_XOR_WriteProcessMemory_37a0 {
  strings:
    $key_37a0 = { 60 d2 [2] 52 f0 [2] 54 c5 [2] 7a c5 [2] 45 d9 }

  condition:
    any of them
}
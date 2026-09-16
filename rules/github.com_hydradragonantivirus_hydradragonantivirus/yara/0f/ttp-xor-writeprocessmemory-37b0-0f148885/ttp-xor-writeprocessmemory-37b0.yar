rule TTP_XOR_WriteProcessMemory_37b0 {
  strings:
    $key_37b0 = { 60 c2 [2] 52 e0 [2] 54 d5 [2] 7a d5 [2] 45 c9 }

  condition:
    any of them
}
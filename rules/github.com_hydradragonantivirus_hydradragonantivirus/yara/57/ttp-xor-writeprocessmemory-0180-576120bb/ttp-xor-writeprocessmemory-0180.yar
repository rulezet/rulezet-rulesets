rule TTP_XOR_WriteProcessMemory_0180 {
  strings:
    $key_0180 = { 56 f2 [2] 64 d0 [2] 62 e5 [2] 4c e5 [2] 73 f9 }

  condition:
    any of them
}
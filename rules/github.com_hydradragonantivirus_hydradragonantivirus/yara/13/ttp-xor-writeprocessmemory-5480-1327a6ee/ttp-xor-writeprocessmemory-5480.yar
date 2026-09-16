rule TTP_XOR_WriteProcessMemory_5480 {
  strings:
    $key_5480 = { 03 f2 [2] 31 d0 [2] 37 e5 [2] 19 e5 [2] 26 f9 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_3280 {
  strings:
    $key_3280 = { 65 f2 [2] 57 d0 [2] 51 e5 [2] 7f e5 [2] 40 f9 }

  condition:
    any of them
}
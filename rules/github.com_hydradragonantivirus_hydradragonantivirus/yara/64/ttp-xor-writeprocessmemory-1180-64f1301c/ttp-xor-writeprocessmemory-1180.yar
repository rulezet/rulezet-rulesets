rule TTP_XOR_WriteProcessMemory_1180 {
  strings:
    $key_1180 = { 46 f2 [2] 74 d0 [2] 72 e5 [2] 5c e5 [2] 63 f9 }

  condition:
    any of them
}
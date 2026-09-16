rule TTP_XOR_WriteProcessMemory_2180 {
  strings:
    $key_2180 = { 76 f2 [2] 44 d0 [2] 42 e5 [2] 6c e5 [2] 53 f9 }

  condition:
    any of them
}
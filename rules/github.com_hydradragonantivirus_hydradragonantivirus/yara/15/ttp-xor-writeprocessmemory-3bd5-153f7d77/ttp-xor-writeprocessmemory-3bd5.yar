rule TTP_XOR_WriteProcessMemory_3bd5 {
  strings:
    $key_3bd5 = { 6c a7 [2] 5e 85 [2] 58 b0 [2] 76 b0 [2] 49 ac }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_6bd5 {
  strings:
    $key_6bd5 = { 3c a7 [2] 0e 85 [2] 08 b0 [2] 26 b0 [2] 19 ac }

  condition:
    any of them
}
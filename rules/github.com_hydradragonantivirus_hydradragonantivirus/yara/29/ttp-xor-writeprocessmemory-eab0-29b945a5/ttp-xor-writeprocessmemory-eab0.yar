rule TTP_XOR_WriteProcessMemory_eab0 {
  strings:
    $key_eab0 = { bd c2 [2] 8f e0 [2] 89 d5 [2] a7 d5 [2] 98 c9 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_eab1 {
  strings:
    $key_eab1 = { bd c3 [2] 8f e1 [2] 89 d4 [2] a7 d4 [2] 98 c8 }

  condition:
    any of them
}
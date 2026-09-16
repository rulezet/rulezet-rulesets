rule TTP_XOR_WriteProcessMemory_c891 {
  strings:
    $key_c891 = { 9f e3 [2] ad c1 [2] ab f4 [2] 85 f4 [2] ba e8 }

  condition:
    any of them
}
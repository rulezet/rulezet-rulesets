rule TTP_XOR_WriteProcessMemory_e8b8 {
  strings:
    $key_e8b8 = { bf ca [2] 8d e8 [2] 8b dd [2] a5 dd [2] 9a c1 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_67a7 {
  strings:
    $key_67a7 = { 30 d5 [2] 02 f7 [2] 04 c2 [2] 2a c2 [2] 15 de }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_67a5 {
  strings:
    $key_67a5 = { 30 d7 [2] 02 f5 [2] 04 c0 [2] 2a c0 [2] 15 dc }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_52a5 {
  strings:
    $key_52a5 = { 05 d7 [2] 37 f5 [2] 31 c0 [2] 1f c0 [2] 20 dc }

  condition:
    any of them
}
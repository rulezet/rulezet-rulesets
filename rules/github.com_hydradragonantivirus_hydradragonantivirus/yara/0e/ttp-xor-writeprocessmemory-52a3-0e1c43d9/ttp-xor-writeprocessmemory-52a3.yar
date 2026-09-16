rule TTP_XOR_WriteProcessMemory_52a3 {
  strings:
    $key_52a3 = { 05 d1 [2] 37 f3 [2] 31 c6 [2] 1f c6 [2] 20 da }

  condition:
    any of them
}
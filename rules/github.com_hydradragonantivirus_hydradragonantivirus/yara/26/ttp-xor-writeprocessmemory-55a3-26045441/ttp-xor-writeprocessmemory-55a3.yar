rule TTP_XOR_WriteProcessMemory_55a3 {
  strings:
    $key_55a3 = { 02 d1 [2] 30 f3 [2] 36 c6 [2] 18 c6 [2] 27 da }

  condition:
    any of them
}
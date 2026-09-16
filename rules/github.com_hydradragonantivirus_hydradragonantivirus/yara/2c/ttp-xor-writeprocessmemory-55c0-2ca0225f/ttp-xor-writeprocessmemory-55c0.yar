rule TTP_XOR_WriteProcessMemory_55c0 {
  strings:
    $key_55c0 = { 02 b2 [2] 30 90 [2] 36 a5 [2] 18 a5 [2] 27 b9 }

  condition:
    any of them
}
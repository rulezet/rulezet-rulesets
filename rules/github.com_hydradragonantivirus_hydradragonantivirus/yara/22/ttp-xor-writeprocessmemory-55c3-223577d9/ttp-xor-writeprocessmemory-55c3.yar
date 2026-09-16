rule TTP_XOR_WriteProcessMemory_55c3 {
  strings:
    $key_55c3 = { 02 b1 [2] 30 93 [2] 36 a6 [2] 18 a6 [2] 27 ba }

  condition:
    any of them
}
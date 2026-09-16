rule TTP_XOR_WriteProcessMemory_31c3 {
  strings:
    $key_31c3 = { 66 b1 [2] 54 93 [2] 52 a6 [2] 7c a6 [2] 43 ba }

  condition:
    any of them
}
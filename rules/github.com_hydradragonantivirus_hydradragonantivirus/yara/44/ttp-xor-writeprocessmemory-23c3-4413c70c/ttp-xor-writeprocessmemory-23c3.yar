rule TTP_XOR_WriteProcessMemory_23c3 {
  strings:
    $key_23c3 = { 74 b1 [2] 46 93 [2] 40 a6 [2] 6e a6 [2] 51 ba }

  condition:
    any of them
}
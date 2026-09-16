rule TTP_XOR_WriteProcessMemory_34c3 {
  strings:
    $key_34c3 = { 63 b1 [2] 51 93 [2] 57 a6 [2] 79 a6 [2] 46 ba }

  condition:
    any of them
}
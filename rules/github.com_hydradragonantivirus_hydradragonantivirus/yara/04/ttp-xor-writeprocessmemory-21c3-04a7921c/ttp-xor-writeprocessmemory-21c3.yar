rule TTP_XOR_WriteProcessMemory_21c3 {
  strings:
    $key_21c3 = { 76 b1 [2] 44 93 [2] 42 a6 [2] 6c a6 [2] 53 ba }

  condition:
    any of them
}
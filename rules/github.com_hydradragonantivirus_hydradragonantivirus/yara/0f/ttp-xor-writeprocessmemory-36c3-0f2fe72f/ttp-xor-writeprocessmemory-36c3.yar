rule TTP_XOR_WriteProcessMemory_36c3 {
  strings:
    $key_36c3 = { 61 b1 [2] 53 93 [2] 55 a6 [2] 7b a6 [2] 44 ba }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_14c3 {
  strings:
    $key_14c3 = { 43 b1 [2] 71 93 [2] 77 a6 [2] 59 a6 [2] 66 ba }

  condition:
    any of them
}
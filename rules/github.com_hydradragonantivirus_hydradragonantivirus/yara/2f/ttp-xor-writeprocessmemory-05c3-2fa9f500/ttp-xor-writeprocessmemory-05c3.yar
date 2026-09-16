rule TTP_XOR_WriteProcessMemory_05c3 {
  strings:
    $key_05c3 = { 52 b1 [2] 60 93 [2] 66 a6 [2] 48 a6 [2] 77 ba }

  condition:
    any of them
}
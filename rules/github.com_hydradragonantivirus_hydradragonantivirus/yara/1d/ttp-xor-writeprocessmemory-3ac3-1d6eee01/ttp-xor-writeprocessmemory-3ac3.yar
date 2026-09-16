rule TTP_XOR_WriteProcessMemory_3ac3 {
  strings:
    $key_3ac3 = { 6d b1 [2] 5f 93 [2] 59 a6 [2] 77 a6 [2] 48 ba }

  condition:
    any of them
}
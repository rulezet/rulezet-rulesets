rule TTP_XOR_WriteProcessMemory_ffc3 {
  strings:
    $key_ffc3 = { a8 b1 [2] 9a 93 [2] 9c a6 [2] b2 a6 [2] 8d ba }

  condition:
    any of them
}
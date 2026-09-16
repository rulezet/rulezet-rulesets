rule TTP_XOR_WriteProcessMemory_33c1 {
  strings:
    $key_33c1 = { 64 b3 [2] 56 91 [2] 50 a4 [2] 7e a4 [2] 41 b8 }

  condition:
    any of them
}
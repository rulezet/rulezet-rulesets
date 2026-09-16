rule TTP_XOR_WriteProcessMemory_16c1 {
  strings:
    $key_16c1 = { 41 b3 [2] 73 91 [2] 75 a4 [2] 5b a4 [2] 64 b8 }

  condition:
    any of them
}
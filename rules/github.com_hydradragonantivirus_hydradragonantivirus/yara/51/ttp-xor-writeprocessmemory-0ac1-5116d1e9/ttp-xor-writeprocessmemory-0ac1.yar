rule TTP_XOR_WriteProcessMemory_0ac1 {
  strings:
    $key_0ac1 = { 5d b3 [2] 6f 91 [2] 69 a4 [2] 47 a4 [2] 78 b8 }

  condition:
    any of them
}
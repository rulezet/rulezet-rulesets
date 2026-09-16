rule TTP_XOR_WriteProcessMemory_1ac1 {
  strings:
    $key_1ac1 = { 4d b3 [2] 7f 91 [2] 79 a4 [2] 57 a4 [2] 68 b8 }

  condition:
    any of them
}
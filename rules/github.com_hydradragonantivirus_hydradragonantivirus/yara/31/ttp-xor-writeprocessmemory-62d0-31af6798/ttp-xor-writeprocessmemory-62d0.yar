rule TTP_XOR_WriteProcessMemory_62d0 {
  strings:
    $key_62d0 = { 35 a2 [2] 07 80 [2] 01 b5 [2] 2f b5 [2] 10 a9 }

  condition:
    any of them
}
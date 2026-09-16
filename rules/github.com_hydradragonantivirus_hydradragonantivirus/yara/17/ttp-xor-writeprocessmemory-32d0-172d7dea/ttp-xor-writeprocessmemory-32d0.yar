rule TTP_XOR_WriteProcessMemory_32d0 {
  strings:
    $key_32d0 = { 65 a2 [2] 57 80 [2] 51 b5 [2] 7f b5 [2] 40 a9 }

  condition:
    any of them
}
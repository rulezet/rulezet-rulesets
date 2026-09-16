rule TTP_XOR_WriteProcessMemory_75f8 {
  strings:
    $key_75f8 = { 22 8a [2] 10 a8 [2] 16 9d [2] 38 9d [2] 07 81 }

  condition:
    any of them
}
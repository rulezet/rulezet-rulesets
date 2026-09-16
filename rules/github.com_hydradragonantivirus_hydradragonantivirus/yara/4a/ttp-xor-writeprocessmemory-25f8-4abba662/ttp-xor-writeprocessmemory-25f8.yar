rule TTP_XOR_WriteProcessMemory_25f8 {
  strings:
    $key_25f8 = { 72 8a [2] 40 a8 [2] 46 9d [2] 68 9d [2] 57 81 }

  condition:
    any of them
}
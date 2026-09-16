rule TTP_XOR_WriteProcessMemory_22f8 {
  strings:
    $key_22f8 = { 75 8a [2] 47 a8 [2] 41 9d [2] 6f 9d [2] 50 81 }

  condition:
    any of them
}
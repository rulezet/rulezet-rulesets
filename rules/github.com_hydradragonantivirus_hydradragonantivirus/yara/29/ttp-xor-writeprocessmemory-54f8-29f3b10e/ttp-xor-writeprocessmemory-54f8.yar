rule TTP_XOR_WriteProcessMemory_54f8 {
  strings:
    $key_54f8 = { 03 8a [2] 31 a8 [2] 37 9d [2] 19 9d [2] 26 81 }

  condition:
    any of them
}
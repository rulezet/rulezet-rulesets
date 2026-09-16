rule TTP_XOR_WriteProcessMemory_74f8 {
  strings:
    $key_74f8 = { 23 8a [2] 11 a8 [2] 17 9d [2] 39 9d [2] 06 81 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_44f8 {
  strings:
    $key_44f8 = { 13 8a [2] 21 a8 [2] 27 9d [2] 09 9d [2] 36 81 }

  condition:
    any of them
}
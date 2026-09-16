rule TTP_XOR_WriteProcessMemory_61f8 {
  strings:
    $key_61f8 = { 36 8a [2] 04 a8 [2] 02 9d [2] 2c 9d [2] 13 81 }

  condition:
    any of them
}
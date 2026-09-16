rule TTP_XOR_WriteProcessMemory_61e8 {
  strings:
    $key_61e8 = { 36 9a [2] 04 b8 [2] 02 8d [2] 2c 8d [2] 13 91 }

  condition:
    any of them
}
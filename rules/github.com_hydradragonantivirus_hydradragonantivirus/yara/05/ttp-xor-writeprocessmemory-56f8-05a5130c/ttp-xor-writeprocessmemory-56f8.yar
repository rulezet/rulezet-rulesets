rule TTP_XOR_WriteProcessMemory_56f8 {
  strings:
    $key_56f8 = { 01 8a [2] 33 a8 [2] 35 9d [2] 1b 9d [2] 24 81 }

  condition:
    any of them
}
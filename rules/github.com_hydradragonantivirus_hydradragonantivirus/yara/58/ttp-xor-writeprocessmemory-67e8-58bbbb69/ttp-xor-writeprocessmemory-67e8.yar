rule TTP_XOR_WriteProcessMemory_67e8 {
  strings:
    $key_67e8 = { 30 9a [2] 02 b8 [2] 04 8d [2] 2a 8d [2] 15 91 }

  condition:
    any of them
}
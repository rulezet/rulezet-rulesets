rule TTP_XOR_WriteProcessMemory_55e8 {
  strings:
    $key_55e8 = { 02 9a [2] 30 b8 [2] 36 8d [2] 18 8d [2] 27 91 }

  condition:
    any of them
}
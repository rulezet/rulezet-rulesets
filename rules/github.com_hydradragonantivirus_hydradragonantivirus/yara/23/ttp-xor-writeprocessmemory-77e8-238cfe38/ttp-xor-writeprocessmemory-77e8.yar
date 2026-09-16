rule TTP_XOR_WriteProcessMemory_77e8 {
  strings:
    $key_77e8 = { 20 9a [2] 12 b8 [2] 14 8d [2] 3a 8d [2] 05 91 }

  condition:
    any of them
}
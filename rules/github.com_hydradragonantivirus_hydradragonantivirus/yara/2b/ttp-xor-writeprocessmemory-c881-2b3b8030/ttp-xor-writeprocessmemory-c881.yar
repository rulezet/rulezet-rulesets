rule TTP_XOR_WriteProcessMemory_c881 {
  strings:
    $key_c881 = { 9f f3 [2] ad d1 [2] ab e4 [2] 85 e4 [2] ba f8 }

  condition:
    any of them
}
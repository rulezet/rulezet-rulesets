rule TTP_XOR_WriteProcessMemory_e848 {
  strings:
    $key_e848 = { bf 3a [2] 8d 18 [2] 8b 2d [2] a5 2d [2] 9a 31 }

  condition:
    any of them
}
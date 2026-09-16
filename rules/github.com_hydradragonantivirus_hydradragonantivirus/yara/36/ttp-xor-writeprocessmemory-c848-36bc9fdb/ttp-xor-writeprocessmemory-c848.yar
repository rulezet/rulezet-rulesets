rule TTP_XOR_WriteProcessMemory_c848 {
  strings:
    $key_c848 = { 9f 3a [2] ad 18 [2] ab 2d [2] 85 2d [2] ba 31 }

  condition:
    any of them
}
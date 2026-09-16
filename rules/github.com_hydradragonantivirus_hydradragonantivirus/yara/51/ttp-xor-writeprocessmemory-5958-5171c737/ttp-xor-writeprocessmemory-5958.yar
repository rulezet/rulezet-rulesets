rule TTP_XOR_WriteProcessMemory_5958 {
  strings:
    $key_5958 = { 0e 2a [2] 3c 08 [2] 3a 3d [2] 14 3d [2] 2b 21 }

  condition:
    any of them
}
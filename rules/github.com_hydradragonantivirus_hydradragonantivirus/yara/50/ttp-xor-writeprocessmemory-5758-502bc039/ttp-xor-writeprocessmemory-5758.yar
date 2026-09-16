rule TTP_XOR_WriteProcessMemory_5758 {
  strings:
    $key_5758 = { 00 2a [2] 32 08 [2] 34 3d [2] 1a 3d [2] 25 21 }

  condition:
    any of them
}
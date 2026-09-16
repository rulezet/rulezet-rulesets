rule TTP_XOR_WriteProcessMemory_5258 {
  strings:
    $key_5258 = { 05 2a [2] 37 08 [2] 31 3d [2] 1f 3d [2] 20 21 }

  condition:
    any of them
}
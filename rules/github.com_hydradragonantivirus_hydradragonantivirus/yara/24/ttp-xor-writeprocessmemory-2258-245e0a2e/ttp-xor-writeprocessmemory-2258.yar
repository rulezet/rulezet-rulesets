rule TTP_XOR_WriteProcessMemory_2258 {
  strings:
    $key_2258 = { 75 2a [2] 47 08 [2] 41 3d [2] 6f 3d [2] 50 21 }

  condition:
    any of them
}
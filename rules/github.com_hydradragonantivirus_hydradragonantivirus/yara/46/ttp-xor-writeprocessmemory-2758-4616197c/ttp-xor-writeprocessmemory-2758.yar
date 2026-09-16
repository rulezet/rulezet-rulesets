rule TTP_XOR_WriteProcessMemory_2758 {
  strings:
    $key_2758 = { 70 2a [2] 42 08 [2] 44 3d [2] 6a 3d [2] 55 21 }

  condition:
    any of them
}
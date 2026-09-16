rule TTP_XOR_WriteProcessMemory_2748 {
  strings:
    $key_2748 = { 70 3a [2] 42 18 [2] 44 2d [2] 6a 2d [2] 55 31 }

  condition:
    any of them
}
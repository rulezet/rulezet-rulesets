rule TTP_XOR_WriteProcessMemory_2468 {
  strings:
    $key_2468 = { 73 1a [2] 41 38 [2] 47 0d [2] 69 0d [2] 56 11 }

  condition:
    any of them
}
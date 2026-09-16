rule TTP_XOR_WriteProcessMemory_0848 {
  strings:
    $key_0848 = { 5f 3a [2] 6d 18 [2] 6b 2d [2] 45 2d [2] 7a 31 }

  condition:
    any of them
}
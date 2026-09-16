rule TTP_XOR_WriteProcessMemory_0e48 {
  strings:
    $key_0e48 = { 59 3a [2] 6b 18 [2] 6d 2d [2] 43 2d [2] 7c 31 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_1f48 {
  strings:
    $key_1f48 = { 48 3a [2] 7a 18 [2] 7c 2d [2] 52 2d [2] 6d 31 }

  condition:
    any of them
}
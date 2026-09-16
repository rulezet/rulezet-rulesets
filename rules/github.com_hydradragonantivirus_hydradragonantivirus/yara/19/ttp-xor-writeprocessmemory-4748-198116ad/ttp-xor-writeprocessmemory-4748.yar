rule TTP_XOR_WriteProcessMemory_4748 {
  strings:
    $key_4748 = { 10 3a [2] 22 18 [2] 24 2d [2] 0a 2d [2] 35 31 }

  condition:
    any of them
}
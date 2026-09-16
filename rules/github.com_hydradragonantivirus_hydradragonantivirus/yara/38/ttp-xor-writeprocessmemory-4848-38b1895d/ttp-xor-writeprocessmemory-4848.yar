rule TTP_XOR_WriteProcessMemory_4848 {
  strings:
    $key_4848 = { 1f 3a [2] 2d 18 [2] 2b 2d [2] 05 2d [2] 3a 31 }

  condition:
    any of them
}
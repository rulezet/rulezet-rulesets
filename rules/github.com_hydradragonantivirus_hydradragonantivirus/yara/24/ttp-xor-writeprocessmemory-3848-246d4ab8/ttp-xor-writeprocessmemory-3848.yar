rule TTP_XOR_WriteProcessMemory_3848 {
  strings:
    $key_3848 = { 6f 3a [2] 5d 18 [2] 5b 2d [2] 75 2d [2] 4a 31 }

  condition:
    any of them
}
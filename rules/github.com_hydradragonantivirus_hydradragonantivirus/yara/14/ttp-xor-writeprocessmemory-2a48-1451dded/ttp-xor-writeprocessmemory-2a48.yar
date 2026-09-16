rule TTP_XOR_WriteProcessMemory_2a48 {
  strings:
    $key_2a48 = { 7d 3a [2] 4f 18 [2] 49 2d [2] 67 2d [2] 58 31 }

  condition:
    any of them
}
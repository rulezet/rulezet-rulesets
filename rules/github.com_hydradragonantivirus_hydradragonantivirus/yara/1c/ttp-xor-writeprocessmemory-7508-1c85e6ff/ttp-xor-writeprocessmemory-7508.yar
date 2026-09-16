rule TTP_XOR_WriteProcessMemory_7508 {
  strings:
    $key_7508 = { 22 7a [2] 10 58 [2] 16 6d [2] 38 6d [2] 07 71 }

  condition:
    any of them
}
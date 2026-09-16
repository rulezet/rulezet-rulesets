rule TTP_XOR_WriteProcessMemory_3768 {
  strings:
    $key_3768 = { 60 1a [2] 52 38 [2] 54 0d [2] 7a 0d [2] 45 11 }

  condition:
    any of them
}
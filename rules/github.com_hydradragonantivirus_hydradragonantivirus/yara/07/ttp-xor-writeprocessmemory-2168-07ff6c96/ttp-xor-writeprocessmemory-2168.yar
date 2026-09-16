rule TTP_XOR_WriteProcessMemory_2168 {
  strings:
    $key_2168 = { 76 1a [2] 44 38 [2] 42 0d [2] 6c 0d [2] 53 11 }

  condition:
    any of them
}
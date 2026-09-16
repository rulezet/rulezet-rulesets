rule TTP_XOR_WriteProcessMemory_2768 {
  strings:
    $key_2768 = { 70 1a [2] 42 38 [2] 44 0d [2] 6a 0d [2] 55 11 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_2778 {
  strings:
    $key_2778 = { 70 0a [2] 42 28 [2] 44 1d [2] 6a 1d [2] 55 01 }

  condition:
    any of them
}
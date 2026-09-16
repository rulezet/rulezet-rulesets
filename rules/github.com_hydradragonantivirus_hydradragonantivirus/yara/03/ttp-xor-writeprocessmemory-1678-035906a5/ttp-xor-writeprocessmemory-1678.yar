rule TTP_XOR_WriteProcessMemory_1678 {
  strings:
    $key_1678 = { 41 0a [2] 73 28 [2] 75 1d [2] 5b 1d [2] 64 01 }

  condition:
    any of them
}
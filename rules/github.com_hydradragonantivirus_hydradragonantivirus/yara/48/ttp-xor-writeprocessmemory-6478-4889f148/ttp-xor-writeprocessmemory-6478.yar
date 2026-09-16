rule TTP_XOR_WriteProcessMemory_6478 {
  strings:
    $key_6478 = { 33 0a [2] 01 28 [2] 07 1d [2] 29 1d [2] 16 01 }

  condition:
    any of them
}
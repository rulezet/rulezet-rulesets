rule TTP_XOR_WriteProcessMemory_6678 {
  strings:
    $key_6678 = { 31 0a [2] 03 28 [2] 05 1d [2] 2b 1d [2] 14 01 }

  condition:
    any of them
}
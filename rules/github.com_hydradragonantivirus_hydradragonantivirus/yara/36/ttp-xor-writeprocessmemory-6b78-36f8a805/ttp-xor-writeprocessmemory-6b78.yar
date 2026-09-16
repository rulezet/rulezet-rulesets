rule TTP_XOR_WriteProcessMemory_6b78 {
  strings:
    $key_6b78 = { 3c 0a [2] 0e 28 [2] 08 1d [2] 26 1d [2] 19 01 }

  condition:
    any of them
}
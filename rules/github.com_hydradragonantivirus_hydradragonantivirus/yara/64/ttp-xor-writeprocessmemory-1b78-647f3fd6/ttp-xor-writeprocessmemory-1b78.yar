rule TTP_XOR_WriteProcessMemory_1b78 {
  strings:
    $key_1b78 = { 4c 0a [2] 7e 28 [2] 78 1d [2] 56 1d [2] 69 01 }

  condition:
    any of them
}
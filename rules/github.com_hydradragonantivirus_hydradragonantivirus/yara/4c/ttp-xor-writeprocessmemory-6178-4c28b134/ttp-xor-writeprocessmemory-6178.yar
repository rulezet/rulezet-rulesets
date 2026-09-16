rule TTP_XOR_WriteProcessMemory_6178 {
  strings:
    $key_6178 = { 36 0a [2] 04 28 [2] 02 1d [2] 2c 1d [2] 13 01 }

  condition:
    any of them
}
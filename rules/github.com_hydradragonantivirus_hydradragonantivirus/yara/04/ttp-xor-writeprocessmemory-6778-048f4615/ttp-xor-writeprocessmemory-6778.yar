rule TTP_XOR_WriteProcessMemory_6778 {
  strings:
    $key_6778 = { 30 0a [2] 02 28 [2] 04 1d [2] 2a 1d [2] 15 01 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_1578 {
  strings:
    $key_1578 = { 42 0a [2] 70 28 [2] 76 1d [2] 58 1d [2] 67 01 }

  condition:
    any of them
}
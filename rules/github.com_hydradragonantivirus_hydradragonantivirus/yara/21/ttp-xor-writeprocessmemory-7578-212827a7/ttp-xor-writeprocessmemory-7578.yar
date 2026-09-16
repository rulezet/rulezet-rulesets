rule TTP_XOR_WriteProcessMemory_7578 {
  strings:
    $key_7578 = { 22 0a [2] 10 28 [2] 16 1d [2] 38 1d [2] 07 01 }

  condition:
    any of them
}
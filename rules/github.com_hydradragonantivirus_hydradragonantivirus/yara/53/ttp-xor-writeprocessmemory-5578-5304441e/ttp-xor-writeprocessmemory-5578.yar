rule TTP_XOR_WriteProcessMemory_5578 {
  strings:
    $key_5578 = { 02 0a [2] 30 28 [2] 36 1d [2] 18 1d [2] 27 01 }

  condition:
    any of them
}
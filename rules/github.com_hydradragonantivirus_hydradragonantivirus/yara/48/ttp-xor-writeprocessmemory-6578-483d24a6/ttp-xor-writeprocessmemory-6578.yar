rule TTP_XOR_WriteProcessMemory_6578 {
  strings:
    $key_6578 = { 32 0a [2] 00 28 [2] 06 1d [2] 28 1d [2] 17 01 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_2578 {
  strings:
    $key_2578 = { 72 0a [2] 40 28 [2] 46 1d [2] 68 1d [2] 57 01 }

  condition:
    any of them
}
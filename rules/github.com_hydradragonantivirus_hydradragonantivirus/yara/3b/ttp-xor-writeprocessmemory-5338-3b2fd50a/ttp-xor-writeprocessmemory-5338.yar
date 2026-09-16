rule TTP_XOR_WriteProcessMemory_5338 {
  strings:
    $key_5338 = { 04 4a [2] 36 68 [2] 30 5d [2] 1e 5d [2] 21 41 }

  condition:
    any of them
}
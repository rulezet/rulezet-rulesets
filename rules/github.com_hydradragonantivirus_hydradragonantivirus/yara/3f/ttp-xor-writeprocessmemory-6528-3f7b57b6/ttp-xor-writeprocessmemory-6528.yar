rule TTP_XOR_WriteProcessMemory_6528 {
  strings:
    $key_6528 = { 32 5a [2] 00 78 [2] 06 4d [2] 28 4d [2] 17 51 }

  condition:
    any of them
}
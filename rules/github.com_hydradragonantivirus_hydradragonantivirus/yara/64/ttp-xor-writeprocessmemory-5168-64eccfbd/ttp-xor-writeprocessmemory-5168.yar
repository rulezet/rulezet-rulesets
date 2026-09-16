rule TTP_XOR_WriteProcessMemory_5168 {
  strings:
    $key_5168 = { 06 1a [2] 34 38 [2] 32 0d [2] 1c 0d [2] 23 11 }

  condition:
    any of them
}
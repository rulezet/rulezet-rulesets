rule TTP_XOR_WriteProcessMemory_7368 {
  strings:
    $key_7368 = { 24 1a [2] 16 38 [2] 10 0d [2] 3e 0d [2] 01 11 }

  condition:
    any of them
}
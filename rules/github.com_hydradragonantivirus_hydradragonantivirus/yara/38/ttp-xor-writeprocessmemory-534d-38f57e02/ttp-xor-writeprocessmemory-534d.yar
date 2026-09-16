rule TTP_XOR_WriteProcessMemory_534d {
  strings:
    $key_534d = { 04 3f [2] 36 1d [2] 30 28 [2] 1e 28 [2] 21 34 }

  condition:
    any of them
}
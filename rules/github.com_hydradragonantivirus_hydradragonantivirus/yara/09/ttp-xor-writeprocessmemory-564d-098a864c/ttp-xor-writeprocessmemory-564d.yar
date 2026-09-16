rule TTP_XOR_WriteProcessMemory_564d {
  strings:
    $key_564d = { 01 3f [2] 33 1d [2] 35 28 [2] 1b 28 [2] 24 34 }

  condition:
    any of them
}
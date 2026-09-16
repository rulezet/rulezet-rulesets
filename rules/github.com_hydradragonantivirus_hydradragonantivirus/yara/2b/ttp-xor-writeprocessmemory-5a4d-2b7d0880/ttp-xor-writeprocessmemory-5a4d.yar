rule TTP_XOR_WriteProcessMemory_5a4d {
  strings:
    $key_5a4d = { 0d 3f [2] 3f 1d [2] 39 28 [2] 17 28 [2] 28 34 }

  condition:
    any of them
}
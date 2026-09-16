rule TTP_XOR_WriteProcessMemory_424d {
  strings:
    $key_424d = { 15 3f [2] 27 1d [2] 21 28 [2] 0f 28 [2] 30 34 }

  condition:
    any of them
}
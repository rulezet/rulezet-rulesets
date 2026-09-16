rule TTP_XOR_WriteProcessMemory_264d {
  strings:
    $key_264d = { 71 3f [2] 43 1d [2] 45 28 [2] 6b 28 [2] 54 34 }

  condition:
    any of them
}
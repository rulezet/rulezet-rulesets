rule TTP_XOR_WriteProcessMemory_344d {
  strings:
    $key_344d = { 63 3f [2] 51 1d [2] 57 28 [2] 79 28 [2] 46 34 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_324d {
  strings:
    $key_324d = { 65 3f [2] 57 1d [2] 51 28 [2] 7f 28 [2] 40 34 }

  condition:
    any of them
}
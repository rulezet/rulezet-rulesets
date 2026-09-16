rule TTP_XOR_WriteProcessMemory_004d {
  strings:
    $key_004d = { 57 3f [2] 65 1d [2] 63 28 [2] 4d 28 [2] 72 34 }

  condition:
    any of them
}
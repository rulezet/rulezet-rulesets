rule TTP_XOR_WriteProcessMemory_744d {
  strings:
    $key_744d = { 23 3f [2] 11 1d [2] 17 28 [2] 39 28 [2] 06 34 }

  condition:
    any of them
}
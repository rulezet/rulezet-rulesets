rule TTP_XOR_WriteProcessMemory_484d {
  strings:
    $key_484d = { 1f 3f [2] 2d 1d [2] 2b 28 [2] 05 28 [2] 3a 34 }

  condition:
    any of them
}
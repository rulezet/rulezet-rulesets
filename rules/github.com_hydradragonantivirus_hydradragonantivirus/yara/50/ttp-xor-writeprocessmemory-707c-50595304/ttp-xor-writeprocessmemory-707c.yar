rule TTP_XOR_WriteProcessMemory_707c {
  strings:
    $key_707c = { 27 0e [2] 15 2c [2] 13 19 [2] 3d 19 [2] 02 05 }

  condition:
    any of them
}
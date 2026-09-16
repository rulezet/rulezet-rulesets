rule TTP_XOR_WriteProcessMemory_7a5e {
  strings:
    $key_7a5e = { 2d 2c [2] 1f 0e [2] 19 3b [2] 37 3b [2] 08 27 }

  condition:
    any of them
}
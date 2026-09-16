rule TTP_XOR_WriteProcessMemory_525e {
  strings:
    $key_525e = { 05 2c [2] 37 0e [2] 31 3b [2] 1f 3b [2] 20 27 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_145e {
  strings:
    $key_145e = { 43 2c [2] 71 0e [2] 77 3b [2] 59 3b [2] 66 27 }

  condition:
    any of them
}
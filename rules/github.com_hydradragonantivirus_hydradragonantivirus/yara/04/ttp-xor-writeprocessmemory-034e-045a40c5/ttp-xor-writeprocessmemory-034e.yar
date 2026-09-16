rule TTP_XOR_WriteProcessMemory_034e {
  strings:
    $key_034e = { 54 3c [2] 66 1e [2] 60 2b [2] 4e 2b [2] 71 37 }

  condition:
    any of them
}
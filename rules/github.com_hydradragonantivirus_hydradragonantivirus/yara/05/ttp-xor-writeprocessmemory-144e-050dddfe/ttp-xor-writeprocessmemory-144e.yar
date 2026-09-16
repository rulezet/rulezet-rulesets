rule TTP_XOR_WriteProcessMemory_144e {
  strings:
    $key_144e = { 43 3c [2] 71 1e [2] 77 2b [2] 59 2b [2] 66 37 }

  condition:
    any of them
}
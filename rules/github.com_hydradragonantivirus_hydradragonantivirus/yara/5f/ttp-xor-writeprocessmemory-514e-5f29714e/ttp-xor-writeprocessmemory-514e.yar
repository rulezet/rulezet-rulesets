rule TTP_XOR_WriteProcessMemory_514e {
  strings:
    $key_514e = { 06 3c [2] 34 1e [2] 32 2b [2] 1c 2b [2] 23 37 }

  condition:
    any of them
}
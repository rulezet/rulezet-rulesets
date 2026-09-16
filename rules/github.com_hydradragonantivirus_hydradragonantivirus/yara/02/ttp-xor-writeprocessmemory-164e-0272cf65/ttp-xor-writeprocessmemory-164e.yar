rule TTP_XOR_WriteProcessMemory_164e {
  strings:
    $key_164e = { 41 3c [2] 73 1e [2] 75 2b [2] 5b 2b [2] 64 37 }

  condition:
    any of them
}
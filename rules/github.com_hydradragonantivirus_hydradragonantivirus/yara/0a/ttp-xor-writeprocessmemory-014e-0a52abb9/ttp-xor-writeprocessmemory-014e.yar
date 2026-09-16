rule TTP_XOR_WriteProcessMemory_014e {
  strings:
    $key_014e = { 56 3c [2] 64 1e [2] 62 2b [2] 4c 2b [2] 73 37 }

  condition:
    any of them
}
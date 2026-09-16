rule TTP_XOR_WriteProcessMemory_214e {
  strings:
    $key_214e = { 76 3c [2] 44 1e [2] 42 2b [2] 6c 2b [2] 53 37 }

  condition:
    any of them
}
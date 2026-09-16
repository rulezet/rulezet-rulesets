rule TTP_XOR_WriteProcessMemory_044e {
  strings:
    $key_044e = { 53 3c [2] 61 1e [2] 67 2b [2] 49 2b [2] 76 37 }

  condition:
    any of them
}
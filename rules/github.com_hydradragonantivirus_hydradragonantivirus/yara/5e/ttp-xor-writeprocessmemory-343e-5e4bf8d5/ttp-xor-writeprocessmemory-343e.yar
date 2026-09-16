rule TTP_XOR_WriteProcessMemory_343e {
  strings:
    $key_343e = { 63 4c [2] 51 6e [2] 57 5b [2] 79 5b [2] 46 47 }

  condition:
    any of them
}
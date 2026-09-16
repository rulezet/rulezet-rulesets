rule TTP_XOR_WriteProcessMemory_424e {
  strings:
    $key_424e = { 15 3c [2] 27 1e [2] 21 2b [2] 0f 2b [2] 30 37 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_174e {
  strings:
    $key_174e = { 40 3c [2] 72 1e [2] 74 2b [2] 5a 2b [2] 65 37 }

  condition:
    any of them
}
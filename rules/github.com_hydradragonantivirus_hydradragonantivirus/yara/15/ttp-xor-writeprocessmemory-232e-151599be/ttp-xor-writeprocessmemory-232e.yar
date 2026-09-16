rule TTP_XOR_WriteProcessMemory_232e {
  strings:
    $key_232e = { 74 5c [2] 46 7e [2] 40 4b [2] 6e 4b [2] 51 57 }

  condition:
    any of them
}
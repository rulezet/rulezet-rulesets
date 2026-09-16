rule TTP_XOR_WriteProcessMemory_f35e {
  strings:
    $key_f35e = { a4 2c [2] 96 0e [2] 90 3b [2] be 3b [2] 81 27 }

  condition:
    any of them
}
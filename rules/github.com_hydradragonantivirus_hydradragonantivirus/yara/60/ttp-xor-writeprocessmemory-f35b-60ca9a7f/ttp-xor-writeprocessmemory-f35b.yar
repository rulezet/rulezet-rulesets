rule TTP_XOR_WriteProcessMemory_f35b {
  strings:
    $key_f35b = { a4 29 [2] 96 0b [2] 90 3e [2] be 3e [2] 81 22 }

  condition:
    any of them
}
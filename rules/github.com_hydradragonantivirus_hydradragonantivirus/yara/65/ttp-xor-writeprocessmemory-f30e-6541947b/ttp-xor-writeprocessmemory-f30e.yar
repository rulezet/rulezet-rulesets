rule TTP_XOR_WriteProcessMemory_f30e {
  strings:
    $key_f30e = { a4 7c [2] 96 5e [2] 90 6b [2] be 6b [2] 81 77 }

  condition:
    any of them
}
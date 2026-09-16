rule TTP_XOR_WriteProcessMemory_f31e {
  strings:
    $key_f31e = { a4 6c [2] 96 4e [2] 90 7b [2] be 7b [2] 81 67 }

  condition:
    any of them
}
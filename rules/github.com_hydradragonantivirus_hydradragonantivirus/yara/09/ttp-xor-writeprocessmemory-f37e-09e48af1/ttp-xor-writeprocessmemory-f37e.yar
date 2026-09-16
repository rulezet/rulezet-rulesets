rule TTP_XOR_WriteProcessMemory_f37e {
  strings:
    $key_f37e = { a4 0c [2] 96 2e [2] 90 1b [2] be 1b [2] 81 07 }

  condition:
    any of them
}
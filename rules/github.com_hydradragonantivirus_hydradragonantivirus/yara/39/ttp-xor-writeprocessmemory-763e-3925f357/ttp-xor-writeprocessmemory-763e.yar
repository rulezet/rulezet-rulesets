rule TTP_XOR_WriteProcessMemory_763e {
  strings:
    $key_763e = { 21 4c [2] 13 6e [2] 15 5b [2] 3b 5b [2] 04 47 }

  condition:
    any of them
}
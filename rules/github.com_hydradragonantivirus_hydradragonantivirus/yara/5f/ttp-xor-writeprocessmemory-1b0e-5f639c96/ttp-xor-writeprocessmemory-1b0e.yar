rule TTP_XOR_WriteProcessMemory_1b0e {
  strings:
    $key_1b0e = { 4c 7c [2] 7e 5e [2] 78 6b [2] 56 6b [2] 69 77 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_4b0e {
  strings:
    $key_4b0e = { 1c 7c [2] 2e 5e [2] 28 6b [2] 06 6b [2] 39 77 }

  condition:
    any of them
}
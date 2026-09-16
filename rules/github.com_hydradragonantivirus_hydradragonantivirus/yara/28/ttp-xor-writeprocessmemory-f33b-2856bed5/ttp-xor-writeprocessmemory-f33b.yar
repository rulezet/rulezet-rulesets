rule TTP_XOR_WriteProcessMemory_f33b {
  strings:
    $key_f33b = { a4 49 [2] 96 6b [2] 90 5e [2] be 5e [2] 81 42 }

  condition:
    any of them
}
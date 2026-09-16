rule TTP_XOR_WriteProcessMemory_f37b {
  strings:
    $key_f37b = { a4 09 [2] 96 2b [2] 90 1e [2] be 1e [2] 81 02 }

  condition:
    any of them
}
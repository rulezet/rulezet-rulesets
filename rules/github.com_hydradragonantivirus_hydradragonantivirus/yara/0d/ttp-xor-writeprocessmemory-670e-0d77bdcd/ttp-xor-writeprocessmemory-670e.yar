rule TTP_XOR_WriteProcessMemory_670e {
  strings:
    $key_670e = { 30 7c [2] 02 5e [2] 04 6b [2] 2a 6b [2] 15 77 }

  condition:
    any of them
}
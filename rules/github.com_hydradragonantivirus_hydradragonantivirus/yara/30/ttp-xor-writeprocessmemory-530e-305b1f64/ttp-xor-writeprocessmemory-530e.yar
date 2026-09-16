rule TTP_XOR_WriteProcessMemory_530e {
  strings:
    $key_530e = { 04 7c [2] 36 5e [2] 30 6b [2] 1e 6b [2] 21 77 }

  condition:
    any of them
}
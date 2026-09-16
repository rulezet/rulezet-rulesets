rule TTP_XOR_WriteProcessMemory_450e {
  strings:
    $key_450e = { 12 7c [2] 20 5e [2] 26 6b [2] 08 6b [2] 37 77 }

  condition:
    any of them
}
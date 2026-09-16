rule TTP_XOR_WriteProcessMemory_6d0e {
  strings:
    $key_6d0e = { 3a 7c [2] 08 5e [2] 0e 6b [2] 20 6b [2] 1f 77 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_6d2e {
  strings:
    $key_6d2e = { 3a 5c [2] 08 7e [2] 0e 4b [2] 20 4b [2] 1f 57 }

  condition:
    any of them
}
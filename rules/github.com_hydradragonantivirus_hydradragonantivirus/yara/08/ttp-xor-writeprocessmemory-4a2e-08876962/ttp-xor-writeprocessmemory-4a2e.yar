rule TTP_XOR_WriteProcessMemory_4a2e {
  strings:
    $key_4a2e = { 1d 5c [2] 2f 7e [2] 29 4b [2] 07 4b [2] 38 57 }

  condition:
    any of them
}
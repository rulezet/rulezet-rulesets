rule TTP_XOR_WriteProcessMemory_1a2e {
  strings:
    $key_1a2e = { 4d 5c [2] 7f 7e [2] 79 4b [2] 57 4b [2] 68 57 }

  condition:
    any of them
}
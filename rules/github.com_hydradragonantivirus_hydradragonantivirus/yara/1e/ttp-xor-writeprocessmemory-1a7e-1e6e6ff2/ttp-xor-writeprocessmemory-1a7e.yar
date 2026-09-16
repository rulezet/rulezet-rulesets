rule TTP_XOR_WriteProcessMemory_1a7e {
  strings:
    $key_1a7e = { 4d 0c [2] 7f 2e [2] 79 1b [2] 57 1b [2] 68 07 }

  condition:
    any of them
}
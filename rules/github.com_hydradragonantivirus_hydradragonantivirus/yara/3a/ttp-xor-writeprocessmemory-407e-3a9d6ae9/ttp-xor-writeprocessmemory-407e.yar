rule TTP_XOR_WriteProcessMemory_407e {
  strings:
    $key_407e = { 17 0c [2] 25 2e [2] 23 1b [2] 0d 1b [2] 32 07 }

  condition:
    any of them
}
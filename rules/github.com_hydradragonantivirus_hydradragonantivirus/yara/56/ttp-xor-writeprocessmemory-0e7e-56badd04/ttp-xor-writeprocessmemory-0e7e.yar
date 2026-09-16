rule TTP_XOR_WriteProcessMemory_0e7e {
  strings:
    $key_0e7e = { 59 0c [2] 6b 2e [2] 6d 1b [2] 43 1b [2] 7c 07 }

  condition:
    any of them
}
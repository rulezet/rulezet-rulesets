rule TTP_XOR_WriteProcessMemory_487e {
  strings:
    $key_487e = { 1f 0c [2] 2d 2e [2] 2b 1b [2] 05 1b [2] 3a 07 }

  condition:
    any of them
}
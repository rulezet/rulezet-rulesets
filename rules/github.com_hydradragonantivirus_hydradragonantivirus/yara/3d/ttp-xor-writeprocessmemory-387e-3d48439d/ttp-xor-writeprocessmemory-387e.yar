rule TTP_XOR_WriteProcessMemory_387e {
  strings:
    $key_387e = { 6f 0c [2] 5d 2e [2] 5b 1b [2] 75 1b [2] 4a 07 }

  condition:
    any of them
}
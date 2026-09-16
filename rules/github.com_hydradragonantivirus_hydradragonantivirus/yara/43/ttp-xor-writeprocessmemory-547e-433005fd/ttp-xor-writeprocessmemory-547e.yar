rule TTP_XOR_WriteProcessMemory_547e {
  strings:
    $key_547e = { 03 0c [2] 31 2e [2] 37 1b [2] 19 1b [2] 26 07 }

  condition:
    any of them
}
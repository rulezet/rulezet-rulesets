rule TTP_XOR_WriteProcessMemory_667e {
  strings:
    $key_667e = { 31 0c [2] 03 2e [2] 05 1b [2] 2b 1b [2] 14 07 }

  condition:
    any of them
}
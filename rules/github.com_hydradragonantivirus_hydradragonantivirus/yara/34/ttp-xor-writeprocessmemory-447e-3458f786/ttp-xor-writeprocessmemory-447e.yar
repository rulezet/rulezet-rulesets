rule TTP_XOR_WriteProcessMemory_447e {
  strings:
    $key_447e = { 13 0c [2] 21 2e [2] 27 1b [2] 09 1b [2] 36 07 }

  condition:
    any of them
}
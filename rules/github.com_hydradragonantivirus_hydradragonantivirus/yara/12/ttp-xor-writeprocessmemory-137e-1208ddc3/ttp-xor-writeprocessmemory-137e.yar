rule TTP_XOR_WriteProcessMemory_137e {
  strings:
    $key_137e = { 44 0c [2] 76 2e [2] 70 1b [2] 5e 1b [2] 61 07 }

  condition:
    any of them
}
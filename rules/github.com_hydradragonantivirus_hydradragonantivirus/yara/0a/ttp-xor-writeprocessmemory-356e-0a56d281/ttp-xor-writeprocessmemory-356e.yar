rule TTP_XOR_WriteProcessMemory_356e {
  strings:
    $key_356e = { 62 1c [2] 50 3e [2] 56 0b [2] 78 0b [2] 47 17 }

  condition:
    any of them
}
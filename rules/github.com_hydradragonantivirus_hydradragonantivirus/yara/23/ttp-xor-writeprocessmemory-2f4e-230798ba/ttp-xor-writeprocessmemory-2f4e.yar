rule TTP_XOR_WriteProcessMemory_2f4e {
  strings:
    $key_2f4e = { 78 3c [2] 4a 1e [2] 4c 2b [2] 62 2b [2] 5d 37 }

  condition:
    any of them
}
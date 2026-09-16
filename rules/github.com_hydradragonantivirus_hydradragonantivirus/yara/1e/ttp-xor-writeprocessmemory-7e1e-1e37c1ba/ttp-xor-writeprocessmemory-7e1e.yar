rule TTP_XOR_WriteProcessMemory_7e1e {
  strings:
    $key_7e1e = { 29 6c [2] 1b 4e [2] 1d 7b [2] 33 7b [2] 0c 67 }

  condition:
    any of them
}
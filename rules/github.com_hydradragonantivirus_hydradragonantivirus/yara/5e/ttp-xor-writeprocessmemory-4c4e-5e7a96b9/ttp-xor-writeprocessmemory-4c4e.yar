rule TTP_XOR_WriteProcessMemory_4c4e {
  strings:
    $key_4c4e = { 1b 3c [2] 29 1e [2] 2f 2b [2] 01 2b [2] 3e 37 }

  condition:
    any of them
}
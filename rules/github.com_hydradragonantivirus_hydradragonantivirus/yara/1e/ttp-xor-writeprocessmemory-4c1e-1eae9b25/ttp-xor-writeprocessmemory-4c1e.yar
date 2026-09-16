rule TTP_XOR_WriteProcessMemory_4c1e {
  strings:
    $key_4c1e = { 1b 6c [2] 29 4e [2] 2f 7b [2] 01 7b [2] 3e 67 }

  condition:
    any of them
}
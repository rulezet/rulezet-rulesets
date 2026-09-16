rule TTP_XOR_WriteProcessMemory_4c2e {
  strings:
    $key_4c2e = { 1b 5c [2] 29 7e [2] 2f 4b [2] 01 4b [2] 3e 57 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_4c3e {
  strings:
    $key_4c3e = { 1b 4c [2] 29 6e [2] 2f 5b [2] 01 5b [2] 3e 47 }

  condition:
    any of them
}
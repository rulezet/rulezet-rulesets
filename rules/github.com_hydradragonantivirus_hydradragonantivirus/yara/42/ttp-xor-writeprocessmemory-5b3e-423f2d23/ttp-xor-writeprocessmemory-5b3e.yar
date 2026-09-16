rule TTP_XOR_WriteProcessMemory_5b3e {
  strings:
    $key_5b3e = { 0c 4c [2] 3e 6e [2] 38 5b [2] 16 5b [2] 29 47 }

  condition:
    any of them
}
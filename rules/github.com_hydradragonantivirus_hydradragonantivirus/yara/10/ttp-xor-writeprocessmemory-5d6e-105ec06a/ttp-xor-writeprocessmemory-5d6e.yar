rule TTP_XOR_WriteProcessMemory_5d6e {
  strings:
    $key_5d6e = { 0a 1c [2] 38 3e [2] 3e 0b [2] 10 0b [2] 2f 17 }

  condition:
    any of them
}
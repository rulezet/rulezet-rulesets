rule TTP_XOR_WriteProcessMemory_4c6e {
  strings:
    $key_4c6e = { 1b 1c [2] 29 3e [2] 2f 0b [2] 01 0b [2] 3e 17 }

  condition:
    any of them
}
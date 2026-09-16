rule TTP_XOR_WriteProcessMemory_516e {
  strings:
    $key_516e = { 06 1c [2] 34 3e [2] 32 0b [2] 1c 0b [2] 23 17 }

  condition:
    any of them
}
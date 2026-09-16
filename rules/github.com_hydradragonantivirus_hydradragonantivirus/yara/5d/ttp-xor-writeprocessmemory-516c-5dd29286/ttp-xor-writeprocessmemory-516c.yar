rule TTP_XOR_WriteProcessMemory_516c {
  strings:
    $key_516c = { 06 1e [2] 34 3c [2] 32 09 [2] 1c 09 [2] 23 15 }

  condition:
    any of them
}
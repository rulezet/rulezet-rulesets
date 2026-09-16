rule TTP_XOR_WriteProcessMemory_29eb {
  strings:
    $key_29eb = { 7e 99 [2] 4c bb [2] 4a 8e [2] 64 8e [2] 5b 92 }

  condition:
    any of them
}
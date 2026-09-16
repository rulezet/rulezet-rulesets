rule TTP_XOR_WriteProcessMemory_512e {
  strings:
    $key_512e = { 06 5c [2] 34 7e [2] 32 4b [2] 1c 4b [2] 23 57 }

  condition:
    any of them
}
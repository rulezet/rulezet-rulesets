rule TTP_XOR_WriteProcessMemory_736c {
  strings:
    $key_736c = { 24 1e [2] 16 3c [2] 10 09 [2] 3e 09 [2] 01 15 }

  condition:
    any of them
}
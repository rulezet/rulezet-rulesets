rule TTP_XOR_WriteProcessMemory_4c6c {
  strings:
    $key_4c6c = { 1b 1e [2] 29 3c [2] 2f 09 [2] 01 09 [2] 3e 15 }

  condition:
    any of them
}
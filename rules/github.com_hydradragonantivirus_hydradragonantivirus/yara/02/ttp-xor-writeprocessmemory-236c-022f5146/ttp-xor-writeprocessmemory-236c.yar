rule TTP_XOR_WriteProcessMemory_236c {
  strings:
    $key_236c = { 74 1e [2] 46 3c [2] 40 09 [2] 6e 09 [2] 51 15 }

  condition:
    any of them
}
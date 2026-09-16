rule TTP_XOR_WriteProcessMemory_436c {
  strings:
    $key_436c = { 14 1e [2] 26 3c [2] 20 09 [2] 0e 09 [2] 31 15 }

  condition:
    any of them
}
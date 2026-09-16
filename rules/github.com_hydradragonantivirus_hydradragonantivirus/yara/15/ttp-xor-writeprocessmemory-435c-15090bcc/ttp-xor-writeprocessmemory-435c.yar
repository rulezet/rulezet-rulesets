rule TTP_XOR_WriteProcessMemory_435c {
  strings:
    $key_435c = { 14 2e [2] 26 0c [2] 20 39 [2] 0e 39 [2] 31 25 }

  condition:
    any of them
}
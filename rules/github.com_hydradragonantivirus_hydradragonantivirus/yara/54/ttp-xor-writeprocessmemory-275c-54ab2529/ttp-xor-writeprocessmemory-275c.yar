rule TTP_XOR_WriteProcessMemory_275c {
  strings:
    $key_275c = { 70 2e [2] 42 0c [2] 44 39 [2] 6a 39 [2] 55 25 }

  condition:
    any of them
}
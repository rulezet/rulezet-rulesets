rule TTP_XOR_WriteProcessMemory_735c {
  strings:
    $key_735c = { 24 2e [2] 16 0c [2] 10 39 [2] 3e 39 [2] 01 25 }

  condition:
    any of them
}
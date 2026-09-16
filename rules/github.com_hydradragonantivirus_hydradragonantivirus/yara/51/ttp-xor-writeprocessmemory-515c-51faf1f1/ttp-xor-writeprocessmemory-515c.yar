rule TTP_XOR_WriteProcessMemory_515c {
  strings:
    $key_515c = { 06 2e [2] 34 0c [2] 32 39 [2] 1c 39 [2] 23 25 }

  condition:
    any of them
}
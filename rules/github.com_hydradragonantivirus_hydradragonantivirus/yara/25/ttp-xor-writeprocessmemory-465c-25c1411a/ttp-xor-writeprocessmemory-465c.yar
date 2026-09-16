rule TTP_XOR_WriteProcessMemory_465c {
  strings:
    $key_465c = { 11 2e [2] 23 0c [2] 25 39 [2] 0b 39 [2] 34 25 }

  condition:
    any of them
}
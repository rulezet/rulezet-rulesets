rule TTP_XOR_WriteProcessMemory_505c {
  strings:
    $key_505c = { 07 2e [2] 35 0c [2] 33 39 [2] 1d 39 [2] 22 25 }

  condition:
    any of them
}
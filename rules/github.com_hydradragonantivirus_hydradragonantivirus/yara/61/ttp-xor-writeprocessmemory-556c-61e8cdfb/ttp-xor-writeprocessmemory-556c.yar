rule TTP_XOR_WriteProcessMemory_556c {
  strings:
    $key_556c = { 02 1e [2] 30 3c [2] 36 09 [2] 18 09 [2] 27 15 }

  condition:
    any of them
}
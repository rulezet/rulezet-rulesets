rule TTP_XOR_WriteProcessMemory_225c {
  strings:
    $key_225c = { 75 2e [2] 47 0c [2] 41 39 [2] 6f 39 [2] 50 25 }

  condition:
    any of them
}
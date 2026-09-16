rule TTP_XOR_WriteProcessMemory_4bec {
  strings:
    $key_4bec = { 1c 9e [2] 2e bc [2] 28 89 [2] 06 89 [2] 39 95 }

  condition:
    any of them
}
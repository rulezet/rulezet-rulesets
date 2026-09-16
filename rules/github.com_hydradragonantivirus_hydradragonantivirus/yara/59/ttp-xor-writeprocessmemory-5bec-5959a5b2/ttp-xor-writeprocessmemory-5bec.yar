rule TTP_XOR_WriteProcessMemory_5bec {
  strings:
    $key_5bec = { 0c 9e [2] 3e bc [2] 38 89 [2] 16 89 [2] 29 95 }

  condition:
    any of them
}
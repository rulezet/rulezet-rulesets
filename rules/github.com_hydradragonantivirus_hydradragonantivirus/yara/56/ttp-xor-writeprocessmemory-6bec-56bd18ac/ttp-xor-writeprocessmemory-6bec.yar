rule TTP_XOR_WriteProcessMemory_6bec {
  strings:
    $key_6bec = { 3c 9e [2] 0e bc [2] 08 89 [2] 26 89 [2] 19 95 }

  condition:
    any of them
}
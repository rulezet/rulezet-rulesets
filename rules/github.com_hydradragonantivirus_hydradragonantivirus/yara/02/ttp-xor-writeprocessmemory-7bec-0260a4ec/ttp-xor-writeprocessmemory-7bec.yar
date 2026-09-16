rule TTP_XOR_WriteProcessMemory_7bec {
  strings:
    $key_7bec = { 2c 9e [2] 1e bc [2] 18 89 [2] 36 89 [2] 09 95 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_612e {
  strings:
    $key_612e = { 36 5c [2] 04 7e [2] 02 4b [2] 2c 4b [2] 13 57 }

  condition:
    any of them
}
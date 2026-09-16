rule TTP_XOR_WriteProcessMemory_457e {
  strings:
    $key_457e = { 12 0c [2] 20 2e [2] 26 1b [2] 08 1b [2] 37 07 }

  condition:
    any of them
}
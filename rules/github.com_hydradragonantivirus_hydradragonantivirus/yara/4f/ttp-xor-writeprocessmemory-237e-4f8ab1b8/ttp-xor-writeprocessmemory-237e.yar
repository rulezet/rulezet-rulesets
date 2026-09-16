rule TTP_XOR_WriteProcessMemory_237e {
  strings:
    $key_237e = { 74 0c [2] 46 2e [2] 40 1b [2] 6e 1b [2] 51 07 }

  condition:
    any of them
}
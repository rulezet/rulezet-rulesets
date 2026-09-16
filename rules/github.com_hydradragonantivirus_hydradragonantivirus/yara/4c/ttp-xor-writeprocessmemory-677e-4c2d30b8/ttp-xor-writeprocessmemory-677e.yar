rule TTP_XOR_WriteProcessMemory_677e {
  strings:
    $key_677e = { 30 0c [2] 02 2e [2] 04 1b [2] 2a 1b [2] 15 07 }

  condition:
    any of them
}
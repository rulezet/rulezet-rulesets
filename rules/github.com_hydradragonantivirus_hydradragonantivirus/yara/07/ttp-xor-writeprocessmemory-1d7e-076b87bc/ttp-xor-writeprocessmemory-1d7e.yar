rule TTP_XOR_WriteProcessMemory_1d7e {
  strings:
    $key_1d7e = { 4a 0c [2] 78 2e [2] 7e 1b [2] 50 1b [2] 6f 07 }

  condition:
    any of them
}
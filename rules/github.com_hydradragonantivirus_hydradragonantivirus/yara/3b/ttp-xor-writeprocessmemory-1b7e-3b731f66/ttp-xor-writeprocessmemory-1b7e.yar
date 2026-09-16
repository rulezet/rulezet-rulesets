rule TTP_XOR_WriteProcessMemory_1b7e {
  strings:
    $key_1b7e = { 4c 0c [2] 7e 2e [2] 78 1b [2] 56 1b [2] 69 07 }

  condition:
    any of them
}
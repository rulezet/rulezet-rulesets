rule TTP_XOR_WriteProcessMemory_1b1e {
  strings:
    $key_1b1e = { 4c 6c [2] 7e 4e [2] 78 7b [2] 56 7b [2] 69 67 }

  condition:
    any of them
}
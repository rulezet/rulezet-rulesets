rule TTP_XOR_WriteProcessMemory_1e7e {
  strings:
    $key_1e7e = { 49 0c [2] 7b 2e [2] 7d 1b [2] 53 1b [2] 6c 07 }

  condition:
    any of them
}
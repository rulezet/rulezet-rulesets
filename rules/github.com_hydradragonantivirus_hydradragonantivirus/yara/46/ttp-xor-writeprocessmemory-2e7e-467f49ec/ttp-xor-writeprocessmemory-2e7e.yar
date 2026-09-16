rule TTP_XOR_WriteProcessMemory_2e7e {
  strings:
    $key_2e7e = { 79 0c [2] 4b 2e [2] 4d 1b [2] 63 1b [2] 5c 07 }

  condition:
    any of them
}
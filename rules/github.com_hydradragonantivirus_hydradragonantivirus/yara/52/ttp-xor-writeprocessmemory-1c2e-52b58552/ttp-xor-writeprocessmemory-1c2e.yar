rule TTP_XOR_WriteProcessMemory_1c2e {
  strings:
    $key_1c2e = { 4b 5c [2] 79 7e [2] 7f 4b [2] 51 4b [2] 6e 57 }

  condition:
    any of them
}
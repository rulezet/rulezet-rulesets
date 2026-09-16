rule TTP_XOR_WriteProcessMemory_1c1e {
  strings:
    $key_1c1e = { 4b 6c [2] 79 4e [2] 7f 7b [2] 51 7b [2] 6e 67 }

  condition:
    any of them
}
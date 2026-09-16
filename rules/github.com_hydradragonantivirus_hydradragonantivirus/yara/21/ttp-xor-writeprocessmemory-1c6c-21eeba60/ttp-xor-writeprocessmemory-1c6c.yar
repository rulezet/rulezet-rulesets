rule TTP_XOR_WriteProcessMemory_1c6c {
  strings:
    $key_1c6c = { 4b 1e [2] 79 3c [2] 7f 09 [2] 51 09 [2] 6e 15 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_6b1e {
  strings:
    $key_6b1e = { 3c 6c [2] 0e 4e [2] 08 7b [2] 26 7b [2] 19 67 }

  condition:
    any of them
}
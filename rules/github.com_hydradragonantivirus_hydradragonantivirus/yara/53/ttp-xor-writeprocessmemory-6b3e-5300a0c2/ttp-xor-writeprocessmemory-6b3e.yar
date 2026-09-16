rule TTP_XOR_WriteProcessMemory_6b3e {
  strings:
    $key_6b3e = { 3c 4c [2] 0e 6e [2] 08 5b [2] 26 5b [2] 19 47 }

  condition:
    any of them
}
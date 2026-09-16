rule TTP_XOR_WriteProcessMemory_626e {
  strings:
    $key_626e = { 35 1c [2] 07 3e [2] 01 0b [2] 2f 0b [2] 10 17 }

  condition:
    any of them
}
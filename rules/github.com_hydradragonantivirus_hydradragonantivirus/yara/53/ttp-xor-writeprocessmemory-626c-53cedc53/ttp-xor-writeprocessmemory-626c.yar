rule TTP_XOR_WriteProcessMemory_626c {
  strings:
    $key_626c = { 35 1e [2] 07 3c [2] 01 09 [2] 2f 09 [2] 10 15 }

  condition:
    any of them
}
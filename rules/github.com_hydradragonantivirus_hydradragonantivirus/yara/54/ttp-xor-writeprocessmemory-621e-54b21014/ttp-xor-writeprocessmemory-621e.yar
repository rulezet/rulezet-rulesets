rule TTP_XOR_WriteProcessMemory_621e {
  strings:
    $key_621e = { 35 6c [2] 07 4e [2] 01 7b [2] 2f 7b [2] 10 67 }

  condition:
    any of them
}
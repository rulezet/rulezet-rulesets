rule TTP_XOR_WriteProcessMemory_2d7e {
  strings:
    $key_2d7e = { 7a 0c [2] 48 2e [2] 4e 1b [2] 60 1b [2] 5f 07 }

  condition:
    any of them
}
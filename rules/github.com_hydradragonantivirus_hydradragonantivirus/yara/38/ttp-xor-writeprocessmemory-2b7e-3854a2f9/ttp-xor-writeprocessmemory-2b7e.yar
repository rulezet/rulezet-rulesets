rule TTP_XOR_WriteProcessMemory_2b7e {
  strings:
    $key_2b7e = { 7c 0c [2] 4e 2e [2] 48 1b [2] 66 1b [2] 59 07 }

  condition:
    any of them
}
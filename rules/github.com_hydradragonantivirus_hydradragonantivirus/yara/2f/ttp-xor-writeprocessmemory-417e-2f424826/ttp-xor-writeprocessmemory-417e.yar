rule TTP_XOR_WriteProcessMemory_417e {
  strings:
    $key_417e = { 16 0c [2] 24 2e [2] 22 1b [2] 0c 1b [2] 33 07 }

  condition:
    any of them
}
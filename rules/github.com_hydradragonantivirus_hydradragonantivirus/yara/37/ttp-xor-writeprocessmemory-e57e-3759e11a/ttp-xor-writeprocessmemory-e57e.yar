rule TTP_XOR_WriteProcessMemory_e57e {
  strings:
    $key_e57e = { b2 0c [2] 80 2e [2] 86 1b [2] a8 1b [2] 97 07 }

  condition:
    any of them
}
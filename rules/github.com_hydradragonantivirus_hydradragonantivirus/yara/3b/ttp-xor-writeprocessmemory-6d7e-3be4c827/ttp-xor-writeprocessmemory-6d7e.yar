rule TTP_XOR_WriteProcessMemory_6d7e {
  strings:
    $key_6d7e = { 3a 0c [2] 08 2e [2] 0e 1b [2] 20 1b [2] 1f 07 }

  condition:
    any of them
}
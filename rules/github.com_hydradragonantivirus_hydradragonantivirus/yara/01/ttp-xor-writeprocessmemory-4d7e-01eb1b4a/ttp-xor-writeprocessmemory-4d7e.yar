rule TTP_XOR_WriteProcessMemory_4d7e {
  strings:
    $key_4d7e = { 1a 0c [2] 28 2e [2] 2e 1b [2] 00 1b [2] 3f 07 }

  condition:
    any of them
}
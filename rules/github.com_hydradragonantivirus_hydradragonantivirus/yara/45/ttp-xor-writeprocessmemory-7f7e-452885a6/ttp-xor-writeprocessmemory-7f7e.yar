rule TTP_XOR_WriteProcessMemory_7f7e {
  strings:
    $key_7f7e = { 28 0c [2] 1a 2e [2] 1c 1b [2] 32 1b [2] 0d 07 }

  condition:
    any of them
}
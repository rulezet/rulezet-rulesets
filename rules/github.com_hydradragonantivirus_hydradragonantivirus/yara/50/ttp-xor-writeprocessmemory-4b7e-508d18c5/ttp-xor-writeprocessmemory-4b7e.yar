rule TTP_XOR_WriteProcessMemory_4b7e {
  strings:
    $key_4b7e = { 1c 0c [2] 2e 2e [2] 28 1b [2] 06 1b [2] 39 07 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_737e {
  strings:
    $key_737e = { 24 0c [2] 16 2e [2] 10 1b [2] 3e 1b [2] 01 07 }

  condition:
    any of them
}
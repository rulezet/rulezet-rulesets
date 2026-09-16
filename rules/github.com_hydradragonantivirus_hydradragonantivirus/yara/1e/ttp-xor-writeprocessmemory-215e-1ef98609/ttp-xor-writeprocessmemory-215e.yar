rule TTP_XOR_WriteProcessMemory_215e {
  strings:
    $key_215e = { 76 2c [2] 44 0e [2] 42 3b [2] 6c 3b [2] 53 27 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_015e {
  strings:
    $key_015e = { 56 2c [2] 64 0e [2] 62 3b [2] 4c 3b [2] 73 27 }

  condition:
    any of them
}
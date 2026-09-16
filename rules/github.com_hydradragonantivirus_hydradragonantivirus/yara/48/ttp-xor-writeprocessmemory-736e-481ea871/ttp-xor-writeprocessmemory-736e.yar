rule TTP_XOR_WriteProcessMemory_736e {
  strings:
    $key_736e = { 24 1c [2] 16 3e [2] 10 0b [2] 3e 0b [2] 01 17 }

  condition:
    any of them
}
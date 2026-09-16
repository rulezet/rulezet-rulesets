rule TTP_XOR_WriteProcessMemory_595e {
  strings:
    $key_595e = { 0e 2c [2] 3c 0e [2] 3a 3b [2] 14 3b [2] 2b 27 }

  condition:
    any of them
}
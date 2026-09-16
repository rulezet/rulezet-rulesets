rule TTP_XOR_WriteProcessMemory_492b {
  strings:
    $key_492b = { 1e 59 [2] 2c 7b [2] 2a 4e [2] 04 4e [2] 3b 52 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_792b {
  strings:
    $key_792b = { 2e 59 [2] 1c 7b [2] 1a 4e [2] 34 4e [2] 0b 52 }

  condition:
    any of them
}
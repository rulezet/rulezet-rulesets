rule TTP_XOR_WriteProcessMemory_195b {
  strings:
    $key_195b = { 4e 29 [2] 7c 0b [2] 7a 3e [2] 54 3e [2] 6b 22 }

  condition:
    any of them
}
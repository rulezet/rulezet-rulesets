rule TTP_XOR_WriteProcessMemory_790e {
  strings:
    $key_790e = { 2e 7c [2] 1c 5e [2] 1a 6b [2] 34 6b [2] 0b 77 }

  condition:
    any of them
}
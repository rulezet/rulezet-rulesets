rule TTP_XOR_WriteProcessMemory_493b {
  strings:
    $key_493b = { 1e 49 [2] 2c 6b [2] 2a 5e [2] 04 5e [2] 3b 42 }

  condition:
    any of them
}
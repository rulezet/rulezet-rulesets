rule TTP_XOR_WriteProcessMemory_495b {
  strings:
    $key_495b = { 1e 29 [2] 2c 0b [2] 2a 3e [2] 04 3e [2] 3b 22 }

  condition:
    any of them
}
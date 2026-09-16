rule TTP_XOR_WriteProcessMemory_613b {
  strings:
    $key_613b = { 36 49 [2] 04 6b [2] 02 5e [2] 2c 5e [2] 13 42 }

  condition:
    any of them
}
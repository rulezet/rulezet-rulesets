rule TTP_XOR_WriteProcessMemory_497b {
  strings:
    $key_497b = { 1e 09 [2] 2c 2b [2] 2a 1e [2] 04 1e [2] 3b 02 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_2c7b {
  strings:
    $key_2c7b = { 7b 09 [2] 49 2b [2] 4f 1e [2] 61 1e [2] 5e 02 }

  condition:
    any of them
}
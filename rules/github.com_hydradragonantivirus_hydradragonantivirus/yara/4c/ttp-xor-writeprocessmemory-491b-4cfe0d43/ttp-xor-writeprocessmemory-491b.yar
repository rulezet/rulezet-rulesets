rule TTP_XOR_WriteProcessMemory_491b {
  strings:
    $key_491b = { 1e 69 [2] 2c 4b [2] 2a 7e [2] 04 7e [2] 3b 62 }

  condition:
    any of them
}
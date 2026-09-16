rule TTP_XOR_WriteProcessMemory_611b {
  strings:
    $key_611b = { 36 69 [2] 04 4b [2] 02 7e [2] 2c 7e [2] 13 62 }

  condition:
    any of them
}
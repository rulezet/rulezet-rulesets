rule TTP_XOR_WriteProcessMemory_2c1b {
  strings:
    $key_2c1b = { 7b 69 [2] 49 4b [2] 4f 7e [2] 61 7e [2] 5e 62 }

  condition:
    any of them
}
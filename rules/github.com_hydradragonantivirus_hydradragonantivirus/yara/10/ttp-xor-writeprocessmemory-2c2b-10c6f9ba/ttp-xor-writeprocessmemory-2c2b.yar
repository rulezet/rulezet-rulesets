rule TTP_XOR_WriteProcessMemory_2c2b {
  strings:
    $key_2c2b = { 7b 59 [2] 49 7b [2] 4f 4e [2] 61 4e [2] 5e 52 }

  condition:
    any of them
}
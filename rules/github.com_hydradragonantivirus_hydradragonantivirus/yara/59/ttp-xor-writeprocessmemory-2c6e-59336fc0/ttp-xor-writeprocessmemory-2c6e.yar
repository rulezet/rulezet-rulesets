rule TTP_XOR_WriteProcessMemory_2c6e {
  strings:
    $key_2c6e = { 7b 1c [2] 49 3e [2] 4f 0b [2] 61 0b [2] 5e 17 }

  condition:
    any of them
}
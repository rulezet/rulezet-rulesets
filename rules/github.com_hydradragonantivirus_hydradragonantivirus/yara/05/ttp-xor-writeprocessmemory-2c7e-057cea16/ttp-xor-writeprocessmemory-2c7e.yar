rule TTP_XOR_WriteProcessMemory_2c7e {
  strings:
    $key_2c7e = { 7b 0c [2] 49 2e [2] 4f 1b [2] 61 1b [2] 5e 07 }

  condition:
    any of them
}
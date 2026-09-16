rule TTP_XOR_WriteProcessMemory_2c3e {
  strings:
    $key_2c3e = { 7b 4c [2] 49 6e [2] 4f 5b [2] 61 5b [2] 5e 47 }

  condition:
    any of them
}
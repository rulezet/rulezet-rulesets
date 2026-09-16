rule TTP_XOR_WriteProcessMemory_e85e {
  strings:
    $key_e85e = { bf 2c [2] 8d 0e [2] 8b 3b [2] a5 3b [2] 9a 27 }

  condition:
    any of them
}
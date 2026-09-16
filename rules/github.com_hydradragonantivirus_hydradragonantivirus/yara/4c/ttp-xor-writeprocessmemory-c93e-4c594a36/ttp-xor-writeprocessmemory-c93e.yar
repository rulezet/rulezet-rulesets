rule TTP_XOR_WriteProcessMemory_c93e {
  strings:
    $key_c93e = { 9e 4c [2] ac 6e [2] aa 5b [2] 84 5b [2] bb 47 }

  condition:
    any of them
}
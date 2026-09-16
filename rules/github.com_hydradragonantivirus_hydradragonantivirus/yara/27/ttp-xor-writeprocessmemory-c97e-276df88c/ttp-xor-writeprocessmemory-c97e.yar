rule TTP_XOR_WriteProcessMemory_c97e {
  strings:
    $key_c97e = { 9e 0c [2] ac 2e [2] aa 1b [2] 84 1b [2] bb 07 }

  condition:
    any of them
}
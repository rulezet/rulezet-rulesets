rule TTP_XOR_WriteProcessMemory_e67e {
  strings:
    $key_e67e = { b1 0c [2] 83 2e [2] 85 1b [2] ab 1b [2] 94 07 }

  condition:
    any of them
}
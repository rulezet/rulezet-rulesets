rule TTP_XOR_WriteProcessMemory_e60e {
  strings:
    $key_e60e = { b1 7c [2] 83 5e [2] 85 6b [2] ab 6b [2] 94 77 }

  condition:
    any of them
}
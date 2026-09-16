rule TTP_XOR_WriteProcessMemory_e66e {
  strings:
    $key_e66e = { b1 1c [2] 83 3e [2] 85 0b [2] ab 0b [2] 94 17 }

  condition:
    any of them
}
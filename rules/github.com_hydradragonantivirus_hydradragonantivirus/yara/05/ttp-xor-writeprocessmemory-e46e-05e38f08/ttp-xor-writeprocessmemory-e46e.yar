rule TTP_XOR_WriteProcessMemory_e46e {
  strings:
    $key_e46e = { b3 1c [2] 81 3e [2] 87 0b [2] a9 0b [2] 96 17 }

  condition:
    any of them
}
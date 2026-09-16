rule TTP_XOR_WriteProcessMemory_f56e {
  strings:
    $key_f56e = { a2 1c [2] 90 3e [2] 96 0b [2] b8 0b [2] 87 17 }

  condition:
    any of them
}
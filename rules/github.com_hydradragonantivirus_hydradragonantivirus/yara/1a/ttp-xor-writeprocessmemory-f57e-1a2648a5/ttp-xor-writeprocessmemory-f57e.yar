rule TTP_XOR_WriteProcessMemory_f57e {
  strings:
    $key_f57e = { a2 0c [2] 90 2e [2] 96 1b [2] b8 1b [2] 87 07 }

  condition:
    any of them
}
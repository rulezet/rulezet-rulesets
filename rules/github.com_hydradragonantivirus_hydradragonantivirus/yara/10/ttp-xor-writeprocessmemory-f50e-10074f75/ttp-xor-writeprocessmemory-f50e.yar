rule TTP_XOR_WriteProcessMemory_f50e {
  strings:
    $key_f50e = { a2 7c [2] 90 5e [2] 96 6b [2] b8 6b [2] 87 77 }

  condition:
    any of them
}
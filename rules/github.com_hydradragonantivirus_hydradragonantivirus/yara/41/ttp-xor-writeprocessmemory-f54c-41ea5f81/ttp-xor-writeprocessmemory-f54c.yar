rule TTP_XOR_WriteProcessMemory_f54c {
  strings:
    $key_f54c = { a2 3e [2] 90 1c [2] 96 29 [2] b8 29 [2] 87 35 }

  condition:
    any of them
}
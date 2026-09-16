rule TTP_XOR_WriteProcessMemory_f52c {
  strings:
    $key_f52c = { a2 5e [2] 90 7c [2] 96 49 [2] b8 49 [2] 87 55 }

  condition:
    any of them
}
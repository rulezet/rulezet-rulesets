rule TTP_XOR_WriteProcessMemory_f53c {
  strings:
    $key_f53c = { a2 4e [2] 90 6c [2] 96 59 [2] b8 59 [2] 87 45 }

  condition:
    any of them
}
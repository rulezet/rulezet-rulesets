rule TTP_XOR_WriteProcessMemory_273c {
  strings:
    $key_273c = { 70 4e [2] 42 6c [2] 44 59 [2] 6a 59 [2] 55 45 }

  condition:
    any of them
}
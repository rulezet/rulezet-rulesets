rule TTP_XOR_WriteProcessMemory_632c {
  strings:
    $key_632c = { 34 5e [2] 06 7c [2] 00 49 [2] 2e 49 [2] 11 55 }

  condition:
    any of them
}
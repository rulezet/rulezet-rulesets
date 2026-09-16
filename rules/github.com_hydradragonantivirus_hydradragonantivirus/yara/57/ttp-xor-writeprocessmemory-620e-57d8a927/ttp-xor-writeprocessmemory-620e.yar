rule TTP_XOR_WriteProcessMemory_620e {
  strings:
    $key_620e = { 35 7c [2] 07 5e [2] 01 6b [2] 2f 6b [2] 10 77 }

  condition:
    any of them
}
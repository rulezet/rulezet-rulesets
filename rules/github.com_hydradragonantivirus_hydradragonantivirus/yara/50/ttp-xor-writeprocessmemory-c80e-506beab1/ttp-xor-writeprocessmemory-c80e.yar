rule TTP_XOR_WriteProcessMemory_c80e {
  strings:
    $key_c80e = { 9f 7c [2] ad 5e [2] ab 6b [2] 85 6b [2] ba 77 }

  condition:
    any of them
}
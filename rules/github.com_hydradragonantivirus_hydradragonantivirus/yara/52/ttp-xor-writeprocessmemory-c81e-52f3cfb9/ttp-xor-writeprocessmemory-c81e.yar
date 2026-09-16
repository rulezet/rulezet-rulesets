rule TTP_XOR_WriteProcessMemory_c81e {
  strings:
    $key_c81e = { 9f 6c [2] ad 4e [2] ab 7b [2] 85 7b [2] ba 67 }

  condition:
    any of them
}
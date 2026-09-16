rule TTP_XOR_WriteProcessMemory_680e {
  strings:
    $key_680e = { 3f 7c [2] 0d 5e [2] 0b 6b [2] 25 6b [2] 1a 77 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_410e {
  strings:
    $key_410e = { 16 7c [2] 24 5e [2] 22 6b [2] 0c 6b [2] 33 77 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_020e {
  strings:
    $key_020e = { 55 7c [2] 67 5e [2] 61 6b [2] 4f 6b [2] 70 77 }

  condition:
    any of them
}
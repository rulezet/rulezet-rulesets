rule TTP_XOR_WriteProcessMemory_700e {
  strings:
    $key_700e = { 27 7c [2] 15 5e [2] 13 6b [2] 3d 6b [2] 02 77 }

  condition:
    any of them
}
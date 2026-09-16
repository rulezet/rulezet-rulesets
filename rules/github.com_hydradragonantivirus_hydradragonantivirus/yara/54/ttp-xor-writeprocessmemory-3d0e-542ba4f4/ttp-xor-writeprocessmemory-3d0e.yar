rule TTP_XOR_WriteProcessMemory_3d0e {
  strings:
    $key_3d0e = { 6a 7c [2] 58 5e [2] 5e 6b [2] 70 6b [2] 4f 77 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_3d4e {
  strings:
    $key_3d4e = { 6a 3c [2] 58 1e [2] 5e 2b [2] 70 2b [2] 4f 37 }

  condition:
    any of them
}
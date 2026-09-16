rule TTP_XOR_WriteProcessMemory_4f1e {
  strings:
    $key_4f1e = { 18 6c [2] 2a 4e [2] 2c 7b [2] 02 7b [2] 3d 67 }

  condition:
    any of them
}
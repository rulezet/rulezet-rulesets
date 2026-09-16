rule TTP_XOR_WriteProcessMemory_3d7b {
  strings:
    $key_3d7b = { 6a 09 [2] 58 2b [2] 5e 1e [2] 70 1e [2] 4f 02 }

  condition:
    any of them
}
rule TTP_XOR_WriteProcessMemory_3d2b {
  strings:
    $key_3d2b = { 6a 59 [2] 58 7b [2] 5e 4e [2] 70 4e [2] 4f 52 }

  condition:
    any of them
}
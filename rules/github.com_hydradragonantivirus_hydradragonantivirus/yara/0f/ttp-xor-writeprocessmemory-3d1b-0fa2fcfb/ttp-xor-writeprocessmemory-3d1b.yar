rule TTP_XOR_WriteProcessMemory_3d1b {
  strings:
    $key_3d1b = { 6a 69 [2] 58 4b [2] 5e 7e [2] 70 7e [2] 4f 62 }

  condition:
    any of them
}
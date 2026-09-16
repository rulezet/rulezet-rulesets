rule TTP_XOR_WriteProcessMemory_702b {
  strings:
    $key_702b = { 27 59 [2] 15 7b [2] 13 4e [2] 3d 4e [2] 02 52 }

  condition:
    any of them
}
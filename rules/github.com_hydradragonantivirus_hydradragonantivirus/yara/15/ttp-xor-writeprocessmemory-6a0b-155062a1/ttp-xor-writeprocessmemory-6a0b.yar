rule TTP_XOR_WriteProcessMemory_6a0b {
  strings:
    $key_6a0b = { 3d 79 [2] 0f 5b [2] 09 6e [2] 27 6e [2] 18 72 }

  condition:
    any of them
}